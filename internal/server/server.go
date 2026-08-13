package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
	"leauth/internal/server/issuer"
	"leauth/internal/server/precheck"
	"leauth/internal/server/store"
)

// openStore открывает базу центра. Общее место для Run и обслуживающих
// команд: мастер-ключ и путь к базе берутся из одного конфига.
func openStore(cfg *Config) (*store.Store, error) {
	cipher, err := store.NewCipher(cfg.MasterKey)
	if err != nil {
		return nil, err
	}
	return store.Open(cfg.DB, cipher)
}

// Revoke отключает прокси: удаляет его токен и снимает с него домены.
// Запускается на центре отдельной командой, потому что нужен ровно
// в тот момент, когда сервер работать продолжает, а конкретному прокси
// доверять больше нельзя.
func Revoke(ctx context.Context, cfg *Config, name string) error {
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := NewAuthenticator(st, cfg.EnrollToken).Revoke(ctx, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("прокси %s в базе нет", name)
		}
		return err
	}

	slog.Info("прокси отключён", "имя", name,
		"дальше", "смените LEAUTH_ENROLL_TOKEN, иначе прокси представится заново")
	return nil
}

// Renew помечает домен как требующий выпуска. Нужен после отзыва прокси:
// ключ, который тот унёс с собой, действует до конца срока сертификата,
// и заменить его иначе нечем — плановое продление начнётся только за
// RENEW_BEFORE до истечения.
//
// Сам выпуск делает планировщик на ближайшем тике, как для нового домена:
// CNAME уже на месте, поэтому вмешательства человека не нужно.
func Renew(ctx context.Context, cfg *Config, domain string) error {
	name, err := api.ValidateDomain(domain)
	if err != nil {
		return err
	}

	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	d, err := st.GetDomain(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("домена %s в базе нет", name)
		}
		return err
	}

	if err := st.SetStatus(ctx, d.ID, api.StatusPendingCNAME, "", 0, time.Time{}); err != nil {
		return err
	}

	slog.Info("домен помечен на перевыпуск", "домен", name,
		"когда", "на ближайшем тике планировщика", "интервал", cfg.CheckInterval)
	return nil
}

// Run поднимает центр: HTTP API, страницу статуса и планировщик.
// Возвращает управление после отмены контекста.
func Run(ctx context.Context, cfg *Config) error {
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	adns, err := acmedns.New(cfg.ACMEDNS.API)
	if err != nil {
		return err
	}

	provider := acmedns.NewProvider(adns, st.AccountFor)
	provider.SetTimeout(cfg.Precheck.Propagation)

	iss, err := issuer.New(ctx, issuer.Config{
		DirectoryURL: cfg.ACME.Directory,
		Email:        cfg.ACME.Email,
		Resolvers:    cfg.Precheck.Resolvers,
	}, provider, st)
	if err != nil {
		return err
	}

	checker := precheck.New(adns, precheck.NewSystemResolvers(cfg.Precheck.Resolvers)...)
	sched := NewScheduler(st, checker, iss, cfg.RenewBefore, cfg.CheckInterval)

	auth := NewAuthenticator(st, cfg.EnrollToken)
	if cfg.EnrollToken == "" {
		slog.Warn("приём новых прокси закрыт: не задан enroll_token")
	}

	mux := NewAPI(st, adns, auth).Routes()

	if cfg.Admin.Password != "" {
		NewStatusPage(st, cfg.Admin.User, cfg.Admin.Password).Register(mux)
	} else {
		slog.Warn("страница статуса выключена: не задан ADMIN_PASSWORD")
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go sched.Run(ctx)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("центр запущен", "адрес", cfg.Listen)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http-сервер: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return srv.Shutdown(shutdownCtx)
	}
}
