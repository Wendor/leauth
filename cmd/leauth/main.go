// Command leauth — центр выпуска сертификатов (режим server)
// и агент на прокси-сервере (режим agent).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"leauth/internal/agent"
	"leauth/internal/envsubst"
	"leauth/internal/server"
)

func usage() {
	fmt.Fprintln(os.Stderr, "использование:")
	fmt.Fprintln(os.Stderr, "  leauth server                  запустить центр (настройки — в переменных окружения)")
	fmt.Fprintln(os.Stderr, "  leauth agent  -config <путь>   запустить агента на прокси")
	fmt.Fprintln(os.Stderr, "  leauth render -in <шаблон> -out <файл>")
	fmt.Fprintln(os.Stderr, "                                 подставить ${VAR} из окружения в конфиг")
	fmt.Fprintln(os.Stderr, "  leauth revoke <имя-прокси>     отозвать токен прокси (на центре)")
	fmt.Fprintln(os.Stderr, "  leauth renew  <домен>          перевыпустить сертификат (на центре)")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	switch os.Args[1] {
	case "server":
		runServer()
	case "agent":
		runAgent(os.Args[2:])
	case "render":
		runRender(os.Args[2:])
	case "revoke":
		runAdmin("отзыв прокси", os.Args[2:], server.Revoke)
	case "renew":
		runAdmin("перевыпуск домена", os.Args[2:], server.Renew)
	default:
		usage()
		os.Exit(2)
	}
}

// runServer поднимает центр. Конфигурации в файле у него нет: всё
// приходит переменными окружения, поэтому развёртывание — это .env.
func runServer() {
	cfg, err := server.LoadConfigFromEnv()
	if err != nil {
		slog.Error("конфиг", "ошибка", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, cfg); err != nil {
		slog.Error("центр остановлен с ошибкой", "ошибка", err)
		os.Exit(1)
	}
}

// runAdmin выполняет разовую операцию над базой центра. Обе команды
// запускаются там же, где работает сервер: база и мастер-ключ берутся
// из того же окружения.
func runAdmin(what string, args []string, do func(context.Context, *server.Config, string) error) {
	if len(args) != 1 || args[0] == "" {
		usage()
		os.Exit(2)
	}

	cfg, err := server.LoadConfigFromEnv()
	if err != nil {
		slog.Error("конфиг", "ошибка", err)
		os.Exit(1)
	}

	if err := do(context.Background(), cfg, args[0]); err != nil {
		slog.Error(what, "ошибка", err)
		os.Exit(1)
	}
}

func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	configPath := fs.String("config", "/etc/leauth/agent.yaml", "путь к конфигу")
	nginxConfig := fs.String("nginx-config", "/etc/nginx/nginx.conf", "путь к генерируемому конфигу nginx")
	fs.Parse(args)

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		slog.Error("конфиг", "ошибка", err)
		os.Exit(1)
	}

	a, err := agent.New(cfg, agent.NewNginx(*nginxConfig))
	if err != nil {
		slog.Error("агент", "ошибка", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := a.Run(ctx); err != nil {
		slog.Error("агент остановлен с ошибкой", "ошибка", err)
		os.Exit(1)
	}
}

// runRender готовит конфиг стороннему сервису, который переменных окружения
// не понимает: acme-dns читает только TOML-файл. Запускается init-контейнером
// перед acme-dns, поэтому все параметры служебной зоны задаются при деплое.
func runRender(args []string) {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	in := fs.String("in", "", "путь к шаблону")
	out := fs.String("out", "", "путь к результату")
	fs.Parse(args)

	if *in == "" || *out == "" {
		usage()
		os.Exit(2)
	}

	if err := renderFile(*in, *out); err != nil {
		slog.Error("рендер конфига", "ошибка", err)
		os.Exit(1)
	}
	slog.Info("конфиг сгенерирован", "из", *in, "в", *out)
}

// renderFile подставляет переменные окружения в шаблон. Файл-результат
// создаётся только при успешной подстановке: acme-dns с пустой зоной
// стартует молча и не отвечает ни на один запрос.
func renderFile(in, out string) error {
	tmpl, err := os.ReadFile(in)
	if err != nil {
		return err
	}

	rendered, err := envsubst.Expand(string(tmpl))
	if err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}

	return os.WriteFile(out, []byte(rendered), 0o644)
}
