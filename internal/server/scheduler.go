package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v4/certificate"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
	"leauth/internal/server/issuer"
	"leauth/internal/server/precheck"
	"leauth/internal/server/store"
)

type Prechecker interface {
	Verify(ctx context.Context, domain string, acct acmedns.Account) error
}

// CertIssuer без контекста: lego его не поддерживает, и обещать отмену
// в интерфейсе было бы враньём. См. issuer.Obtain.
type CertIssuer interface {
	Obtain(domains []string) (*certificate.Resource, error)
}

type Scheduler struct {
	store       *store.Store
	precheck    Prechecker
	issuer      CertIssuer
	renewBefore time.Duration
	interval    time.Duration

	// Now подменяется в тестах.
	Now func() time.Time
}

func NewScheduler(s *store.Store, p Prechecker, i CertIssuer, renewBefore, interval time.Duration) *Scheduler {
	return &Scheduler{
		store:       s,
		precheck:    p,
		issuer:      i,
		renewBefore: renewBefore,
		interval:    interval,
		Now:         time.Now,
	}
}

// Run крутит Tick по таймеру до отмены контекста.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()

	s.Tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick — один проход по всем доменам. Ошибка отдельного домена
// не мешает обработке остальных.
func (s *Scheduler) Tick(ctx context.Context) {
	domains, err := s.store.ListServedDomains(ctx)
	if err != nil {
		slog.Error("не удалось получить список доменов", "ошибка", err)
		return
	}

	for _, d := range domains {
		if ctx.Err() != nil {
			return
		}
		s.processDomain(ctx, d)
	}
}

func (s *Scheduler) processDomain(ctx context.Context, d *store.Domain) {
	now := s.Now()

	if !d.RetryAfter.IsZero() && now.Before(d.RetryAfter) {
		return
	}

	if d.Status == api.StatusActive && !s.needsRenewal(ctx, d, now) {
		return
	}

	if err := s.precheck.Verify(ctx, d.Name, d.Account); err != nil {
		s.recordFailure(ctx, d, err, now)
		return
	}

	if err := s.issue(ctx, d); err != nil {
		s.recordFailure(ctx, d, err, now)
	}
}

// needsRenewal отвечает, пора ли обновлять действующий сертификат.
// Читаются только метаданные: приватный ключ для этого решения не нужен,
// а тик проходит по всем доменам.
func (s *Scheduler) needsRenewal(ctx context.Context, d *store.Domain, now time.Time) bool {
	cert, err := s.store.LatestCertMeta(ctx, d.ID)
	if err != nil {
		// Статус active без сертификата — рассогласование, выпускаем заново.
		return true
	}
	return now.After(cert.NotAfter.Add(-s.renewBefore))
}

func (s *Scheduler) issue(ctx context.Context, d *store.Domain) error {
	if err := s.store.SetStatus(ctx, d.ID, api.StatusIssuing, "", d.FailCount, time.Time{}); err != nil {
		return err
	}

	slog.Info("запрашиваем сертификат", "домен", d.Name, "имена", d.Names())

	res, err := s.issuer.Obtain(d.Names())
	if err != nil {
		return err
	}

	serial, notAfter, err := issuer.ParseCertInfo(res.Certificate)
	if err != nil {
		return err
	}

	err = s.store.SaveCert(ctx, d.ID, store.Cert{
		Serial:     serial,
		FullChain:  string(res.Certificate),
		PrivateKey: string(res.PrivateKey),
		NotAfter:   notAfter,
	})
	if err != nil {
		return err
	}

	slog.Info("сертификат выпущен", "домен", d.Name, "serial", serial, "до", notAfter)

	return s.store.SetStatus(ctx, d.ID, api.StatusActive, "", 0, time.Time{})
}

func (s *Scheduler) recordFailure(ctx context.Context, d *store.Domain, cause error, now time.Time) {
	// Отсутствие CNAME — ожидание действия человека, а не сбой:
	// статус остаётся pending_cname и проверяется каждый тик.
	if errors.Is(cause, precheck.ErrCNAMENotConfigured) {
		slog.Info("ждём CNAME", "домен", d.Name, "cname", d.Account.FullDomain)

		if err := s.store.SetStatus(ctx, d.ID, api.StatusPendingCNAME, cause.Error(), 0, time.Time{}); err != nil {
			slog.Error("не удалось обновить статус", "домен", d.Name, "ошибка", err)
		}
		return
	}

	failCount := d.FailCount + 1
	retryAfter := now.Add(backoff(failCount))

	slog.Error("выпуск не удался",
		"домен", d.Name,
		"попытка", failCount,
		"повтор", retryAfter,
		"ошибка", cause)

	if err := s.store.SetStatus(ctx, d.ID, api.StatusError, cause.Error(), failCount, retryAfter); err != nil {
		slog.Error("не удалось обновить статус", "домен", d.Name, "ошибка", err)
	}
}

// backoff: пять минут с удвоением, потолок — час.
func backoff(failCount int) time.Duration {
	const (
		base  = 5 * time.Minute
		limit = time.Hour
	)

	if failCount < 1 {
		return base
	}

	d := base << (failCount - 1)
	if d > limit || d <= 0 {
		return limit
	}
	return d
}
