# Сборка идёт на архитектуре машины, а не образа: бинарь статический,
# и Go кросс-компилирует его сам. Иначе сборка под чужую платформу
# уходила бы в эмуляцию и занимала минуты вместо секунд.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -o /out/leauth ./cmd/leauth

FROM alpine:3.22
# Привязывает пакет в GHCR к репозиторию: без этой метки он висит
# отдельно от кода и не наследует его видимость.
LABEL org.opencontainers.image.source=https://github.com/Wendor/leauth
RUN apk add --no-cache ca-certificates
COPY --from=build /out/leauth /usr/local/bin/leauth
ENTRYPOINT ["/usr/local/bin/leauth"]
