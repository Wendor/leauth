// Package api содержит типы, общие для центра и агента.
// Имена полей JSON здесь — сетевой контракт между ними.
package api

import "time"

// DomainStatus — состояние домена в машине состояний планировщика.
type DomainStatus string

const (
	// StatusPendingCNAME — домен заведён, но CNAME в зоне клиента ещё не виден.
	StatusPendingCNAME DomainStatus = "pending_cname"
	// StatusIssuing — проверка пройдена, идёт выпуск.
	StatusIssuing DomainStatus = "issuing"
	// StatusActive — действующий сертификат выпущен.
	StatusActive DomainStatus = "active"
	// StatusError — последняя попытка выпуска не удалась, ждём бэкофф.
	StatusError DomainStatus = "error"
)

// CNAMERecord — запись, которую владелец зоны должен прописать один раз.
type CNAMERecord struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// EnrollRequest — заявка прокси на приём. Предъявляется общий токен
// приёма, в ответ выдаётся персональный.
type EnrollRequest struct {
	Name string `json:"name"`
}

type EnrollResponse struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

// SyncCertificate — один сертификат в желаемом состоянии прокси.
type SyncCertificate struct {
	Domain string `json:"domain"`
	// Wildcard — включить в сертификат также *.<domain>.
	Wildcard bool `json:"wildcard"`
	// Serial — серийный номер того, что уже лежит на прокси. Центр
	// прикладывает тело сертификата, только если оно разошлось.
	Serial string `json:"serial,omitempty"`
}

// SyncRequest — весь набор сертификатов, который обслуживает прокси.
// Набор именно полный: домен, пропавший из него, центр снимает
// с обслуживания и перестаёт продлевать.
type SyncRequest struct {
	Certificates []SyncCertificate `json:"certificates"`
}

// SyncDomain — состояние домена и, если серийники разошлись, сам
// сертификат.
type SyncDomain struct {
	DomainResponse
	Cert *CertResponse `json:"cert,omitempty"`
}

type SyncResponse struct {
	Domains []SyncDomain `json:"domains"`
}

type DomainResponse struct {
	Domain    string       `json:"domain"`
	Status    DomainStatus `json:"status"`
	Wildcard  bool         `json:"wildcard"`
	CNAME     CNAMERecord  `json:"cname"`
	Serial    string       `json:"serial,omitempty"`
	NotAfter  *time.Time   `json:"not_after,omitempty"`
	LastError string       `json:"last_error,omitempty"`
}

type CertResponse struct {
	Domain     string    `json:"domain"`
	FullChain  string    `json:"fullchain"`
	PrivateKey string    `json:"privkey"`
	Serial     string    `json:"serial"`
	NotAfter   time.Time `json:"not_after"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
