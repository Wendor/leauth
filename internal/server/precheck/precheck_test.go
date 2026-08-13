package precheck

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"leauth/internal/server/acmedns"
)

type fakeACMEDNS struct {
	lastValue string
	err       error
}

func (f *fakeACMEDNS) Register(ctx context.Context) (acmedns.Account, error) {
	return acmedns.Account{}, errors.New("не должно вызываться")
}

func (f *fakeACMEDNS) SetTXT(ctx context.Context, acct acmedns.Account, value string) error {
	if f.err != nil {
		return f.err
	}
	f.lastValue = value
	return nil
}

// fakeResolver отдаёт то, что записали в acme-dns, если имя запрошено верное.
type fakeResolver struct {
	src      *fakeACMEDNS
	wantName string
	records  []string
	err      error
	queried  string
	// cname — ответ на LookupCNAME. Пустой означает «выяснить не удалось»:
	// по умолчанию проверка идёт дальше пробой, как и до её появления.
	cname    string
	cnameErr error
	cnameN   int
}

func (r *fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	r.queried = name
	if r.err != nil {
		return nil, r.err
	}
	if r.records != nil {
		return r.records, nil
	}
	if name == r.wantName {
		return []string{r.src.lastValue}, nil
	}
	return nil, nil
}

func (r *fakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	r.cnameN++
	if r.cnameErr != nil {
		return "", r.cnameErr
	}
	return r.cname, nil
}

func newChecker(c acmedns.Client, r Resolver) *Checker {
	ch := New(c, r)
	ch.Attempts = 1
	ch.Delay = 0
	return ch
}

func TestVerifySucceedsWhenValueVisible(t *testing.T) {
	fc := &fakeACMEDNS{}
	fr := &fakeResolver{src: fc, wantName: "_acme-challenge.foo.example.com"}

	if err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com", acmedns.Account{SubDomain: "abc"}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if fr.queried != "_acme-challenge.foo.example.com" {
		t.Errorf("запрошено имя %q", fr.queried)
	}
	if len(fc.lastValue) != 43 {
		t.Errorf("длина пробного значения = %d, ожидалось 43", len(fc.lastValue))
	}
}

func TestVerifyFailsWhenCNAMENotConfigured(t *testing.T) {
	fc := &fakeACMEDNS{}
	fr := &fakeResolver{src: fc, records: []string{}}

	err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com", acmedns.Account{})
	if !errors.Is(err, ErrCNAMENotConfigured) {
		t.Fatalf("ошибка = %v, ожидалась ErrCNAMENotConfigured", err)
	}
}

func TestVerifyFailsOnForeignValue(t *testing.T) {
	fc := &fakeACMEDNS{}
	fr := &fakeResolver{src: fc, records: []string{"чужое-значение"}}

	err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com", acmedns.Account{})
	if !errors.Is(err, ErrCNAMENotConfigured) {
		t.Fatalf("ошибка = %v, ожидалась ErrCNAMENotConfigured", err)
	}
}

func TestVerifyPropagatesACMEDNSError(t *testing.T) {
	fc := &fakeACMEDNS{err: errors.New("acme-dns недоступен")}
	fr := &fakeResolver{src: fc}

	err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com", acmedns.Account{})
	if err == nil {
		t.Fatal("ожидалась ошибка записи TXT")
	}
	if errors.Is(err, ErrCNAMENotConfigured) {
		t.Error("недоступность acme-dns не должна выглядеть как отсутствие CNAME")
	}
}

func TestVerifyRetries(t *testing.T) {
	fc := &fakeACMEDNS{}
	fr := &fakeResolver{src: fc, wantName: "_acme-challenge.foo.example.com"}

	ch := New(fc, fr)
	ch.Attempts = 3
	ch.Delay = 0

	if err := ch.Verify(context.Background(), "foo.example.com", acmedns.Account{}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Резолверов настраивают несколько именно затем, чтобы сбой одного не
// останавливал выпуск. Раньше опрашивался только первый, и недоступный
// 1.1.1.1 подвешивал все домены.
func TestVerifyFallsBackToNextResolver(t *testing.T) {
	src := &fakeACMEDNS{}
	broken := &fakeResolver{err: errors.New("резолвер недоступен")}
	working := &fakeResolver{src: src, wantName: "_acme-challenge.foo.example.com"}

	c := New(src, broken, working)
	c.Delay = 0

	if err := c.Verify(context.Background(), "foo.example.com", acmedns.Account{}); err != nil {
		t.Fatalf("Verify: %v — запасной резолвер не был опрошен", err)
	}
	if working.queried == "" {
		t.Error("запасной резолвер не опрошен ни разу")
	}
}

// Одной попытки на резолвер мало не бывает: их число поднимается до числа
// резолверов, иначе последний в списке не был бы опрошен никогда.
func TestVerifyQueriesEveryResolver(t *testing.T) {
	src := &fakeACMEDNS{}

	resolvers := make([]Resolver, 5)
	fakes := make([]*fakeResolver, 5)
	for i := range fakes {
		fakes[i] = &fakeResolver{err: errors.New("нет ответа")}
		resolvers[i] = fakes[i]
	}

	c := New(src, resolvers...)
	c.Delay = 0
	c.Attempts = 1

	if err := c.Verify(context.Background(), "foo.example.com", acmedns.Account{}); err == nil {
		t.Fatal("все резолверы молчат — ожидалась ошибка")
	}

	for i, f := range fakes {
		if f.queried == "" {
			t.Errorf("резолвер %d не опрошен", i)
		}
	}
}

// Без резолверов проверка невозможна, и молча пропускать её нельзя:
// иначе домен ушёл бы в ACME без единой проверки CNAME.
func TestVerifyWithoutResolvers(t *testing.T) {
	if err := New(&fakeACMEDNS{}).Verify(context.Background(), "foo.example.com", acmedns.Account{}); err == nil {
		t.Fatal("проверка без резолверов должна быть ошибкой")
	}
}

// Домен, который ждёт человека, отсеивается по CNAME — без записи в
// acme-dns. Иначе каждый тик планировщика тратил бы на него пробу.
func TestVerifySkipsProbeWhenCNAMEPointsElsewhere(t *testing.T) {
	fc := &fakeACMEDNS{}
	fr := &fakeResolver{src: fc, cname: "_acme-challenge.foo.example.com."}

	err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com",
		acmedns.Account{FullDomain: "acct.acme.example.com"})
	if !errors.Is(err, ErrCNAMENotConfigured) {
		t.Fatalf("ошибка = %v, ожидалась ErrCNAMENotConfigured", err)
	}
	if fc.lastValue != "" {
		t.Error("проба записана в acme-dns, хотя CNAME не настроен")
	}
	if fr.queried != "" {
		t.Error("сделан лишний запрос TXT")
	}
}

// Настроенный CNAME проверку не останавливает: дальше идёт проба.
// Регистр и завершающая точка в ответе резолвера значения не имеют.
func TestVerifyProceedsWhenCNAMEMatches(t *testing.T) {
	for _, target := range []string{
		"acct.acme.example.com",
		"acct.acme.example.com.",
		"ACCT.Acme.Example.COM.",
	} {
		fc := &fakeACMEDNS{}
		fr := &fakeResolver{src: fc, wantName: "_acme-challenge.foo.example.com", cname: target}

		err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com",
			acmedns.Account{FullDomain: "acct.acme.example.com"})
		if err != nil {
			t.Errorf("CNAME %q: Verify: %v", target, err)
		}
		if fc.lastValue == "" {
			t.Errorf("CNAME %q: проба не записана", target)
		}
	}
}

// Молчащий резолвер не должен выглядеть как ненастроенный CNAME: дешёвая
// проверка только отсеивает заведомо неготовые домены, а решает проба.
func TestVerifyFallsBackToProbeWhenCNAMEUnknown(t *testing.T) {
	fc := &fakeACMEDNS{}
	fr := &fakeResolver{
		src:      fc,
		wantName: "_acme-challenge.foo.example.com",
		cnameErr: errors.New("SERVFAIL"),
	}

	err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com",
		acmedns.Account{FullDomain: "acct.acme.example.com"})
	if err != nil {
		t.Fatalf("Verify: %v — неизвестность приняли за отсутствие CNAME", err)
	}
	if fc.lastValue == "" {
		t.Error("проба не записана")
	}
}

// Ответ на CNAME берётся у первого откликнувшегося резолвера.
func TestCNAMEFallsBackToNextResolver(t *testing.T) {
	fc := &fakeACMEDNS{}
	broken := &fakeResolver{cnameErr: errors.New("резолвер недоступен")}
	working := &fakeResolver{src: fc, cname: "чужое.acme.example.com."}

	ch := New(fc, broken, working)
	ch.Delay = 0

	err := ch.Verify(context.Background(), "foo.example.com",
		acmedns.Account{FullDomain: "acct.acme.example.com"})
	if !errors.Is(err, ErrCNAMENotConfigured) {
		t.Fatalf("ошибка = %v, ожидалась ErrCNAMENotConfigured", err)
	}
	if working.cnameN == 0 {
		t.Error("запасной резолвер не опрошен")
	}
}

// NXDOMAIN на _acme-challenge означает, что CNAME ещё не прописан, — это
// самый частый случай ожидания, и ради него проверка и делается. Своих
// адресных записей у этого имени не бывает, поэтому «не найдено» здесь
// однозначно.
func TestVerifySkipsProbeWhenRecordAbsent(t *testing.T) {
	fc := &fakeACMEDNS{}
	fr := &fakeResolver{
		src:      fc,
		cnameErr: &net.DNSError{Err: "no such host", Name: "_acme-challenge.foo.example.com", IsNotFound: true},
	}

	err := newChecker(fc, fr).Verify(context.Background(), "foo.example.com",
		acmedns.Account{FullDomain: "acct.acme.example.com"})
	if !errors.Is(err, ErrCNAMENotConfigured) {
		t.Fatalf("ошибка = %v, ожидалась ErrCNAMENotConfigured", err)
	}
	if fc.lastValue != "" {
		t.Error("проба записана в acme-dns, хотя записи в зоне нет")
	}
	// В сообщении должно быть видно, что именно прописать человеку.
	if !strings.Contains(err.Error(), "acct.acme.example.com") {
		t.Errorf("в ошибке нет цели CNAME: %v", err)
	}
}
