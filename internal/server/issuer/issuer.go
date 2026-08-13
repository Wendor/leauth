// Package issuer выпускает сертификаты в Let's Encrypt через lego.
package issuer

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"leauth/internal/server/store"
)

type Config struct {
	// DirectoryURL — адрес ACME-директории: боевой Let's Encrypt,
	// его staging или pebble в тестах.
	DirectoryURL string
	Email        string
	// Resolvers — резолверы для проверки распространения записей.
	Resolvers []string
}

type Issuer struct {
	client *lego.Client
}

func New(ctx context.Context, cfg Config, provider challenge.Provider, as AccountStore) (*Issuer, error) {
	if cfg.DirectoryURL == "" {
		return nil, errors.New("не задан адрес ACME-директории")
	}

	user, err := loadOrCreateUser(ctx, as, cfg.Email)
	if err != nil {
		return nil, err
	}

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.DirectoryURL
	legoCfg.UserAgent = "leauth"

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("клиент lego: %w", err)
	}

	// Обе встроенные проверки распространения выключены.
	//
	// Авторитативная сначала резолвит имя NS-сервера acme-dns, и выпуск
	// начинает зависеть от того, видно ли это имя из контейнера.
	//
	// Проверка через рекурсивные резолверы выглядит подходящей, но lego
	// шлёт её запросы с RecursionDesired=0 (precheck.go, вызов
	// checkNameserversPropagation с recursive=false). Публичный резолвер
	// на такой запрос отвечает только из кеша, а TTL у записей acme-dns
	// равен секунде — кеш почти всегда пуст, и приходит SERVFAIL.
	// Выпуск в итоге зависел от того, успела ли проверка в ту секунду после
	// разрешающего CNAME запроса, который идёт уже с рекурсией.
	//
	// Содержательную проверку делает precheck центра: он спрашивает
	// резолвер обычным рекурсивным запросом и не пускает домен в ACME,
	// пока CNAME не указывает на выданное имя.
	opts := []dns01.ChallengeOption{
		dns01.DisableAuthoritativeNssPropagationRequirement(),
	}
	if len(cfg.Resolvers) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(cfg.Resolvers))
	}
	if err := client.Challenge.SetDNS01Provider(provider, opts...); err != nil {
		return nil, fmt.Errorf("подключение DNS-01: %w", err)
	}

	if user.reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("регистрация в ACME: %w", err)
		}
		user.reg = reg

		raw, err := json.Marshal(reg)
		if err != nil {
			return nil, fmt.Errorf("сериализация регистрации: %w", err)
		}

		keyPEM, err := encodeECKey(mustECKey(user))
		if err != nil {
			return nil, err
		}
		if err := as.SaveACMEAccount(ctx, store.ACMEAccount{
			Email:            cfg.Email,
			PrivateKeyPEM:    keyPEM,
			RegistrationJSON: raw,
		}); err != nil {
			return nil, err
		}
	}

	return &Issuer{client: client}, nil
}

// Obtain заказывает сертификат на перечисленные имена.
// Первое имя становится CommonName, остальные попадают в SAN.
//
// Контекста в сигнатуре нет намеренно: lego его не принимает, и вызов
// нельзя прервать до истечения собственных таймаутов. Верхнюю границу
// задаёт PROPAGATION_TIMEOUT, поэтому остановка центра ждёт не дольше него.
func (i *Issuer) Obtain(domains []string) (*certificate.Resource, error) {
	if len(domains) == 0 {
		return nil, errors.New("пустой список доменов")
	}

	res, err := i.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("выпуск сертификата для %v: %w", domains, err)
	}
	return res, nil
}

// ParseCertInfo достаёт из цепочки серийный номер и срок действия
// первого (листового) сертификата.
func ParseCertInfo(fullchainPEM []byte) (string, time.Time, error) {
	block, _ := pem.Decode(fullchainPEM)
	if block == nil {
		return "", time.Time{}, errors.New("цепочка не является PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("разбор сертификата: %w", err)
	}

	return cert.SerialNumber.Text(16), cert.NotAfter.UTC(), nil
}
