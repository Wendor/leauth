package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type ACMEConfig struct {
	Directory string
	Email     string
}

type ACMEDNSConfig struct {
	API string
}

type PrecheckConfig struct {
	// Resolvers — рекурсивные резолверы, через которые проверяется, что
	// запись видна снаружи. Их несколько: сбой одного не должен
	// останавливать выпуск, поэтому precheck опрашивает их по кругу.
	Resolvers []string
	// Propagation — сколько ждать появления записи в резолверах.
	Propagation time.Duration
}

type AdminConfig struct {
	User     string
	Password string
}

// Config — настройки центра. Читаются из переменных окружения: файла
// конфигурации у центра нет, поэтому развёртывание сводится к .env
// и docker compose up.
type Config struct {
	Listen        string
	DB            string
	MasterKey     string
	ACME          ACMEConfig
	ACMEDNS       ACMEDNSConfig
	Precheck      PrecheckConfig
	RenewBefore   time.Duration
	CheckInterval time.Duration
	Admin         AdminConfig
	// EnrollToken — общий токен, по которому новый прокси получает свой
	// персональный. Пустой означает, что новые прокси не принимаются.
	EnrollToken string
}

func LoadConfigFromEnv() (*Config, error) {
	var problems []string

	require := func(name string) string {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			problems = append(problems, "не задана переменная "+name)
		}
		return value
	}

	duration := func(name, fallback string) time.Duration {
		raw := env(name, fallback)

		d, err := time.ParseDuration(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s=%q: не разобрать длительность", name, raw))
		}
		return d
	}

	cfg := &Config{
		Listen:    env("LEAUTH_LISTEN", ":8080"),
		DB:        env("LEAUTH_DB", "/data/leauth.db"),
		MasterKey: require("LEAUTH_MASTER_KEY"),
		ACME: ACMEConfig{
			Directory: env("ACME_DIRECTORY", "https://acme-v02.api.letsencrypt.org/directory"),
			Email:     require("ACME_EMAIL"),
		},
		ACMEDNS: ACMEDNSConfig{API: env("ACMEDNS_API", "http://acme-dns:8081")},
		Precheck: PrecheckConfig{
			Resolvers:   resolvers(env("PRECHECK_RESOLVER", "1.1.1.1:53,8.8.8.8:53")),
			Propagation: duration("PROPAGATION_TIMEOUT", "5m"),
		},
		RenewBefore:   duration("RENEW_BEFORE", "720h"),
		CheckInterval: duration("CHECK_INTERVAL", "5m"),
		Admin: AdminConfig{
			User:     env("ADMIN_USER", "admin"),
			Password: os.Getenv("ADMIN_PASSWORD"),
		},
		EnrollToken: os.Getenv("LEAUTH_ENROLL_TOKEN"),
	}

	if len(problems) > 0 {
		return nil, errors.New("конфиг центра: " + strings.Join(problems, "; "))
	}
	return cfg, nil
}

// resolvers разбирает список через запятую и дописывает порт там, где
// его не указали: 1.1.1.1 и 1.1.1.1:53 должны работать одинаково.
//
// Адрес IPv6 сам по себе полон двоеточий, поэтому наличие двоеточия
// портом ещё не является: 2001:4860:4860::8888 — это хост, а
// [2001:4860:4860::8888]:53 — хост с портом.
func resolvers(raw string) []string {
	var out []string

	for item := range strings.SplitSeq(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(item); err != nil {
			item = net.JoinHostPort(item, "53")
		}
		out = append(out, item)
	}
	return out
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
