# --platform=$BUILDPLATFORM: см. комментарий в корневом Dockerfile.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -o /out/leauth ./cmd/leauth

# Готовый бинарь авторизации: своего кода OAuth не пишем.
FROM quay.io/oauth2-proxy/oauth2-proxy:v7.15.3 AS oauth2

FROM nginx:1.29-alpine
LABEL org.opencontainers.image.source=https://github.com/Wendor/leauth
RUN apk add --no-cache ca-certificates
COPY --from=build /out/leauth /usr/local/bin/leauth
COPY --from=oauth2 /bin/oauth2-proxy /usr/local/bin/oauth2-proxy
# Агент выступает init-процессом: он поднимает nginx и oauth2-proxy
# и следит за сертификатами.
ENTRYPOINT ["/usr/local/bin/leauth", "agent"]
CMD ["-config", "/etc/leauth/agent.yaml"]
