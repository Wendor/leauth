package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	base  string
	token string
	hc    *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		base:  strings.TrimSuffix(baseURL, "/"),
		token: token,
		hc:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("сериализация запроса: %w", err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return fmt.Errorf("запрос к центру: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("связь с центром: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("центр ответил %d: %s", resp.StatusCode, readError(resp.Body))
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("разбор ответа центра: %w", err)
	}
	return nil
}

func readError(r io.Reader) string {
	var e ErrorResponse
	if err := json.NewDecoder(r).Decode(&e); err == nil && e.Error != "" {
		return e.Error
	}
	return "без подробностей"
}

// Enroll получает персональный токен прокси по общему токену приёма.
// Вызывается один раз за всё время жизни прокси — дальше используется
// выданный токен.
func Enroll(ctx context.Context, baseURL, enrollToken, name string) (string, error) {
	var out EnrollResponse

	c := NewClient(baseURL, enrollToken)
	if err := c.do(ctx, http.MethodPost, "/api/v1/enroll", EnrollRequest{Name: name}, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("центр принял прокси, но не выдал токен")
	}
	return out.Token, nil
}

// Sync объявляет центру желаемое состояние прокси и получает обратно
// состояние доменов вместе с сертификатами, которых у прокси ещё нет.
func (c *Client) Sync(ctx context.Context, certs []SyncCertificate) (*SyncResponse, error) {
	var out SyncResponse

	if err := c.do(ctx, http.MethodPost, "/api/v1/sync", SyncRequest{Certificates: certs}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
