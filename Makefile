.PHONY: test build images push login tags clean-tree integration proxy e2e up down

# Реестр и целевая платформа публикуемых образов.
REGISTRY ?= ghcr.io/wendor
PLATFORM ?= linux/amd64
GHCR_USER ?= Wendor

# Теги выводятся из git, руками их задавать не нужно. На релизном теге
# vX.Y.Z образ получает его и latest; на любом другом коммите — только
# main-<sha>, чтобы промежуточная сборка не увела за собой latest.
VERSION  := $(shell git describe --tags --exact-match --match 'v*' 2>/dev/null)
REVISION := $(shell git rev-parse --short HEAD)
ifeq ($(VERSION),)
TAGS ?= main-$(REVISION)
else
TAGS ?= $(VERSION) latest
endif

# -t на каждый тег: buildx собирает один раз, а имён вешает сколько дано.
tag_flags = $(foreach t,$(TAGS),-t $(REGISTRY)/$(1):$(t))

build:
	CGO_ENABLED=0 go build -o bin/leauth ./cmd/leauth

test:
	go test ./...

# Какие имена получит следующая сборка.
tags:
	@$(foreach t,$(TAGS),echo $(REGISTRY)/leauth:$(t) $(REGISTRY)/leauth-proxy:$(t);)

# Логин в GHCR токеном gh — отдельный PAT заводить не нужно. Скоупа
# write:packages у токена по умолчанию нет, и добавляется он один раз:
#   gh auth refresh -h github.com -s write:packages
# Права проверяются здесь, потому что сам docker login их не проверяет:
# он пускает любой живой токен, а отказ приходит только на пуше.
# GHCR_TOKEN перекрывает gh — на случай публикации из-под другой учётки.
login:
	@test -n "$$GHCR_TOKEN" || gh auth status >/dev/null 2>&1 || { \
		echo "нет ни GHCR_TOKEN, ни входа в gh: gh auth login"; exit 1; }
	@test -n "$$GHCR_TOKEN" || \
		gh api 'user/packages?package_type=container' >/dev/null 2>&1 || { \
		echo "токену gh не хватает прав на пакеты, добавьте скоуп:"; \
		echo "  gh auth refresh -h github.com -s write:packages"; exit 1; }
	@printf '%s' "$${GHCR_TOKEN:-$$(gh auth token)}" | \
		docker login ghcr.io -u $(GHCR_USER) --password-stdin

# Тег обязан указывать на то, что в нём лежит. Незакоммиченные правки
# попали бы в образ, но не в историю, поэтому публикация их не пускает.
clean-tree:
	@test -z "$$(git status --porcelain)" || test -n "$(ALLOW_DIRTY)" || { \
		echo "рабочее дерево грязное: тег будет врать о содержимом образа"; \
		echo "закоммитьте правки или соберите с ALLOW_DIRTY=1"; \
		exit 1; }

# Локальная сборка образов под целевую платформу серверов.
images:
	docker buildx build --platform $(PLATFORM) \
		$(call tag_flags,leauth) --load .
	docker buildx build --platform $(PLATFORM) -f deploy/proxy/Dockerfile \
		$(call tag_flags,leauth-proxy) --load .

# Публикация в реестр. Образы содержат только бинарь и системные
# CA-сертификаты: конфиги и ключи монтируются на запуске.
push: clean-tree
	docker buildx build --platform $(PLATFORM) \
		$(call tag_flags,leauth) --push .
	docker buildx build --platform $(PLATFORM) -f deploy/proxy/Dockerfile \
		$(call tag_flags,leauth-proxy) --push .

up:
	cd test/integration && docker compose up -d acme-dns pebble
	# Ждём, пока поднимется API acme-dns.
	for i in $$(seq 1 30); do \
		curl -sf -o /dev/null -X POST http://127.0.0.1:8081/register && break; \
		sleep 1; \
	done
	# Достаём корневой сертификат pebble — иначе lego ему не доверится.
	cd test/integration && docker compose cp pebble:/test/certs/pebble.minica.pem ./pebble.minica.pem

down:
	cd test/integration && docker compose down -v
	rm -f test/integration/pebble.minica.pem

# Проверки самого прокси: конфиг скармливается настоящему nginx, запросы
# проходят через него насквозь, а аргументы oauth2-proxy — через тот образ,
# который попадёт в боевой. Общая обвязка из up/down здесь не нужна:
# контейнеры каждый тест поднимает себе сам.
proxy:
	cd test/integration && go test -tags=integration -v -count=1 \
		-run 'TestNginx|TestProxy|TestOAuth2Proxy' .

integration: up
	cd test/integration && go test -tags=integration -v -count=1 \
		-run 'TestIssueThroughPebble|TestPrecheckFailsWithoutCNAME' . ; \
		status=$$? ; cd ../.. ; $(MAKE) down ; exit $$status

e2e: up
	cd test/integration && docker compose up -d --build leauth-server backend leauth-proxy
	cd test/integration && go test -tags=integration -v -count=1 -run TestEndToEnd . ; \
		status=$$? ; cd ../.. ; $(MAKE) down ; exit $$status
