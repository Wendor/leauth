package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
	"leauth/internal/server/store"
)

type API struct {
	store *store.Store
	acme  acmedns.Client
	auth  *Authenticator
}

func NewAPI(s *store.Store, c acmedns.Client, a *Authenticator) *API {
	return &API{store: s, acme: c, auth: a}
}

func (a *API) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll", a.handleEnroll)
	mux.HandleFunc("POST /api/v1/sync", a.handleSync)
	return mux
}

// handleEnroll принимает новый прокси и выдаёт ему персональный токен.
// Общий токен приёма один на установку, персональные — свои у каждого
// прокси: компрометация одного не открывает домены остальных.
func (a *API) handleEnroll(w http.ResponseWriter, r *http.Request) {
	// Право на приём проверяется до чтения тела.
	if err := a.auth.CheckEnroll(r.Header.Get("Authorization")); err != nil {
		a.denyEnroll(w, r, err)
		return
	}

	var req api.EnrollRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	name, token, err := a.auth.Enroll(r.Context(), req.Name)
	switch {
	case errors.Is(err, api.ErrBadClientName):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeInternal(w, "выдача токена прокси", err)
		return
	}

	slog.Info("принят прокси", "имя", name)

	writeJSON(w, http.StatusOK, api.EnrollResponse{Name: name, Token: token})
}

// maxRequestBody с запасом покрывает синхронизацию: даже сотня доменов
// занимает единицы килобайт. Без ограничения одно соединение могло бы
// занять память центра целиком.
const maxRequestBody = 1 << 20

// decodeJSON читает тело запроса с ограничением размера.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(dst)
	if err == nil {
		return true
	}

	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, "тело запроса слишком большое")
	} else {
		writeError(w, http.StatusBadRequest, "некорректный JSON")
	}
	return false
}

// denyEnroll отвечает на отказ в приёме и оставляет след в логе: иначе
// подбор токена приёма не виден вообще ничем.
func (a *API) denyEnroll(w http.ResponseWriter, r *http.Request, err error) {
	slog.Warn("отказ в приёме прокси", "адрес", r.RemoteAddr, "причина", err)

	code := http.StatusUnauthorized
	if errors.Is(err, ErrEnrollClosed) {
		code = http.StatusForbidden
	}
	writeError(w, code, err.Error())
}

// writeInternal прячет детали внутренней ошибки: клиенту хватает кода,
// а текст с подробностями БД остаётся в логе центра.
func writeInternal(w http.ResponseWriter, what string, err error) {
	slog.Error(what, "ошибка", err)
	writeError(w, http.StatusInternalServerError, "внутренняя ошибка центра")
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("не удалось записать ответ", "ошибка", err)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, api.ErrorResponse{Error: msg})
}

// client достаёт имя клиента из заголовка Authorization.
func (a *API) client(w http.ResponseWriter, r *http.Request) (string, bool) {
	name, ok := a.auth.ClientFor(r.Context(), r.Header.Get("Authorization"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "требуется корректный Bearer-токен")
		return "", false
	}
	return name, true
}

func domainResponse(d *store.Domain, c *store.Cert) api.DomainResponse {
	resp := api.DomainResponse{
		Domain:   d.Name,
		Status:   d.Status,
		Wildcard: d.Wildcard,
		CNAME: api.CNAMERecord{
			Name:   "_acme-challenge." + d.Name,
			Target: d.Account.FullDomain,
		},
		LastError: d.LastError,
	}

	if c != nil {
		notAfter := c.NotAfter.UTC()
		resp.Serial = c.Serial
		resp.NotAfter = &notAfter
	}
	return resp
}

// handleSync — единственная ручка для прокси. Прокси присылает весь
// набор сертификатов, который обслуживает, и то, что у него уже лежит;
// центр заводит недостающие домены, снимает пропавшие и возвращает
// состояние вместе с разошедшимися сертификатами.
func (a *API) handleSync(w http.ResponseWriter, r *http.Request) {
	client, ok := a.client(w, r)
	if !ok {
		return
	}

	var req api.SyncRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// Пустой набор снял бы с обслуживания все домены прокси. У агента
	// такого состояния не бывает: конфиг без эндпоинтов он не принимает.
	if len(req.Certificates) == 0 {
		writeError(w, http.StatusBadRequest, "пустой набор сертификатов")
		return
	}

	ctx := r.Context()

	// Набор доменов заменяется только после того, как обработаны все:
	// сбой на одном не должен снимать с обслуживания остальные.
	names := make([]string, 0, len(req.Certificates))
	out := make([]api.SyncDomain, 0, len(req.Certificates))

	for _, c := range req.Certificates {
		name, err := api.ValidateDomain(c.Domain)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		d, code, err := a.claim(ctx, client, name, c.Wildcard)
		if err != nil {
			if code == http.StatusInternalServerError {
				writeInternal(w, "заведение домена", err)
			} else {
				writeError(w, code, err.Error())
			}
			return
		}

		names = append(names, name)
		out = append(out, a.syncDomain(ctx, d, c.Serial))
	}

	if err := a.store.SetClientDomains(ctx, client, names); err != nil {
		writeInternal(w, "запись списка доменов прокси", err)
		return
	}

	writeJSON(w, http.StatusOK, api.SyncResponse{Domains: out})
}

// claim возвращает домен, заводя его при первом обращении. Второй
// результат — код ответа для ошибки.
func (a *API) claim(ctx context.Context, client, name string, wildcard bool) (*store.Domain, int, error) {
	existing, err := a.store.GetDomain(ctx, name)
	switch {
	case err == nil:
		if existing.Wildcard != wildcard {
			return nil, http.StatusConflict,
				fmt.Errorf("домен %s уже заведён с wildcard=%v", name, existing.Wildcard)
		}
		a.noteNewClaimant(ctx, client, existing)
		return existing, 0, nil

	case !errors.Is(err, store.ErrNotFound):
		return nil, http.StatusInternalServerError, err
	}

	acct, err := a.acme.Register(ctx)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}

	created, err := a.store.CreateDomain(ctx, name, wildcard, acct)
	if err != nil {
		// Гонка двух агентов: домен успел завести кто-то другой.
		if existing, getErr := a.store.GetDomain(ctx, name); getErr == nil {
			return existing, 0, nil
		}
		return nil, http.StatusInternalServerError, err
	}

	slog.Info("заведён домен",
		"домен", name,
		"клиент", client,
		"cname", created.Account.FullDomain)

	return created, 0, nil
}

// noteNewClaimant отмечает в логе прокси, впервые заявивший чужой домен.
// Само по себе это законно — так выглядят переезд и балансировка, — но
// вместе с доменом на новый хост уезжает приватный ключ сертификата,
// поэтому событие должно быть видно.
func (a *API) noteNewClaimant(ctx context.Context, client string, d *store.Domain) {
	owners, err := a.store.ClientsForDomain(ctx, d.ID)
	if err != nil {
		slog.Error("клиенты домена", "домен", d.Name, "ошибка", err)
		return
	}
	if len(owners) == 0 || slices.Contains(owners, client) {
		return
	}

	slog.Warn("домен заявлен ещё одним прокси",
		"домен", d.Name,
		"прокси", client,
		"уже обслуживают", owners)
}

// syncDomain собирает ответ по одному домену. Тело сертификата уходит
// прокси, только когда серийники разошлись: они большие, а меняются
// раз в два месяца.
func (a *API) syncDomain(ctx context.Context, d *store.Domain, haveSerial string) api.SyncDomain {
	cert, err := a.store.LatestCert(ctx, d.ID)
	if err != nil {
		return api.SyncDomain{DomainResponse: domainResponse(d, nil)}
	}

	item := api.SyncDomain{DomainResponse: domainResponse(d, cert)}
	if cert.Serial != haveSerial {
		item.Cert = &api.CertResponse{
			Domain:     d.Name,
			FullChain:  cert.FullChain,
			PrivateKey: cert.PrivateKey,
			Serial:     cert.Serial,
			NotAfter:   cert.NotAfter.UTC(),
		}
	}
	return item
}
