// Package store — единственное место, где центр хранит состояние:
// домены, учётные данные acme-dns, выпущенные сертификаты и ACME-аккаунт.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"leauth/internal/api"
	"leauth/internal/server/acmedns"
)

// ErrNotFound возвращается, когда запись отсутствует.
var ErrNotFound = errors.New("запись не найдена")

type Domain struct {
	ID         int64
	Name       string
	Wildcard   bool
	Account    acmedns.Account
	Status     api.DomainStatus
	LastError  string
	FailCount  int
	RetryAfter time.Time
}

// Names возвращает список имён для запроса сертификата:
// базовый домен и, если включено, wildcard.
func (d *Domain) Names() []string { return api.CertNames(d.Name, d.Wildcard) }

type Cert struct {
	Serial     string
	FullChain  string
	PrivateKey string
	NotAfter   time.Time
}

// ACMEAccount — единственный аккаунт центра в Let's Encrypt.
// Ключ обязан переживать перезапуски, иначе при каждом старте
// создавался бы новый аккаунт.
type ACMEAccount struct {
	Email            string
	PrivateKeyPEM    []byte
	RegistrationJSON []byte
}

type Store struct {
	db     *sql.DB
	cipher *Cipher
}

const schema = `
CREATE TABLE IF NOT EXISTS domains (
	id                   INTEGER PRIMARY KEY AUTOINCREMENT,
	name                 TEXT    NOT NULL UNIQUE,
	wildcard             INTEGER NOT NULL DEFAULT 0,
	acmedns_username     TEXT    NOT NULL,
	acmedns_password_enc BLOB    NOT NULL,
	acmedns_fulldomain   TEXT    NOT NULL,
	acmedns_subdomain    TEXT    NOT NULL,
	status               TEXT    NOT NULL,
	last_error           TEXT    NOT NULL DEFAULT '',
	fail_count           INTEGER NOT NULL DEFAULT 0,
	retry_after          INTEGER NOT NULL DEFAULT 0,
	created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	domain_id   INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
	serial      TEXT    NOT NULL,
	fullchain   TEXT    NOT NULL,
	privkey_enc BLOB    NOT NULL,
	not_after   INTEGER NOT NULL,
	issued_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS certs_domain_idx ON certs(domain_id, issued_at DESC);

CREATE TABLE IF NOT EXISTS domain_clients (
	domain_id   INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
	client_name TEXT    NOT NULL,
	PRIMARY KEY (domain_id, client_name)
);

CREATE TABLE IF NOT EXISTS clients (
	name       TEXT    PRIMARY KEY,
	token_hash TEXT    NOT NULL UNIQUE,
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS acme_account (
	id           INTEGER PRIMARY KEY CHECK (id = 1),
	email        TEXT NOT NULL,
	privkey_enc  BLOB NOT NULL,
	registration BLOB NOT NULL
);
`

func Open(path string, c *Cipher) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("открытие БД: %w", err)
	}

	// Драйвер без cgo не сериализует запись сам, а планировщик и HTTP
	// работают с БД параллельно.
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("создание схемы: %w", err)
	}

	return &Store{db: db, cipher: c}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateDomain(ctx context.Context, name string, wildcard bool, acct acmedns.Account) (*Domain, error) {
	pwd, err := s.cipher.Encrypt([]byte(acct.Password))
	if err != nil {
		return nil, fmt.Errorf("шифрование пароля acme-dns: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO domains (name, wildcard, acmedns_username, acmedns_password_enc,
		                     acmedns_fulldomain, acmedns_subdomain, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		name, wildcard, acct.Username, pwd, acct.FullDomain, acct.SubDomain,
		string(api.StatusPendingCNAME), time.Now().Unix())
	if err != nil {
		return nil, fmt.Errorf("создание домена %s: %w", name, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("id домена: %w", err)
	}

	return &Domain{
		ID:       id,
		Name:     name,
		Wildcard: wildcard,
		Account:  acct,
		Status:   api.StatusPendingCNAME,
	}, nil
}

const domainColumns = `
	id, name, wildcard, acmedns_username, acmedns_password_enc,
	acmedns_fulldomain, acmedns_subdomain, status, last_error, fail_count, retry_after`

func (s *Store) scanDomain(sc interface{ Scan(...any) error }) (*Domain, error) {
	var (
		d       Domain
		pwdEnc  []byte
		status  string
		retryAt int64
	)

	err := sc.Scan(&d.ID, &d.Name, &d.Wildcard, &d.Account.Username, &pwdEnc,
		&d.Account.FullDomain, &d.Account.SubDomain, &status, &d.LastError, &d.FailCount, &retryAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("чтение домена: %w", err)
	}

	pwd, err := s.cipher.Decrypt(pwdEnc)
	if err != nil {
		return nil, fmt.Errorf("расшифровка пароля acme-dns для %s: %w", d.Name, err)
	}

	d.Account.Password = string(pwd)
	d.Status = api.DomainStatus(status)
	if retryAt > 0 {
		d.RetryAfter = time.Unix(retryAt, 0)
	}

	return &d, nil
}

func (s *Store) GetDomain(ctx context.Context, name string) (*Domain, error) {
	row := s.db.QueryRowContext(ctx, `SELECT`+domainColumns+` FROM domains WHERE name = ?`, name)
	return s.scanDomain(row)
}

func (s *Store) ListDomains(ctx context.Context) ([]*Domain, error) {
	return s.listDomains(ctx, `SELECT`+domainColumns+` FROM domains ORDER BY name`)
}

// ListServedDomains — домены, которые заявил хотя бы один прокси.
// Планировщик работает только с ними: домен, снятый со всех прокси,
// продлевать незачем, а история и учётка acme-dns у него сохраняются.
func (s *Store) ListServedDomains(ctx context.Context) ([]*Domain, error) {
	return s.listDomains(ctx, `SELECT`+domainColumns+` FROM domains d
		WHERE EXISTS (SELECT 1 FROM domain_clients dc WHERE dc.domain_id = d.id)
		ORDER BY name`)
}

func (s *Store) listDomains(ctx context.Context, query string) ([]*Domain, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("список доменов: %w", err)
	}
	defer rows.Close()

	var out []*Domain
	for rows.Next() {
		d, err := s.scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AccountFor реализует acmedns.AccountLookup.
func (s *Store) AccountFor(ctx context.Context, name string) (acmedns.Account, error) {
	d, err := s.GetDomain(ctx, name)
	if err != nil {
		return acmedns.Account{}, err
	}
	return d.Account, nil
}

func (s *Store) SetStatus(ctx context.Context, id int64, st api.DomainStatus, lastErr string, failCount int, retryAfter time.Time) error {
	var retryAt int64
	if !retryAfter.IsZero() {
		retryAt = retryAfter.Unix()
	}

	_, err := s.db.ExecContext(ctx, `
		UPDATE domains SET status = ?, last_error = ?, fail_count = ?, retry_after = ?
		WHERE id = ?`, string(st), lastErr, failCount, retryAt, id)
	if err != nil {
		return fmt.Errorf("обновление статуса домена %d: %w", id, err)
	}
	return nil
}

func (s *Store) SaveCert(ctx context.Context, domainID int64, c Cert) error {
	key, err := s.cipher.Encrypt([]byte(c.PrivateKey))
	if err != nil {
		return fmt.Errorf("шифрование приватного ключа: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO certs (domain_id, serial, fullchain, privkey_enc, not_after, issued_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		domainID, c.Serial, c.FullChain, key, c.NotAfter.Unix(), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("сохранение сертификата: %w", err)
	}
	return nil
}

func (s *Store) LatestCert(ctx context.Context, domainID int64) (*Cert, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT serial, fullchain, privkey_enc, not_after
		FROM certs WHERE domain_id = ? ORDER BY issued_at DESC, id DESC LIMIT 1`, domainID)

	var (
		c        Cert
		keyEnc   []byte
		notAfter int64
	)

	err := row.Scan(&c.Serial, &c.FullChain, &keyEnc, &notAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("чтение сертификата: %w", err)
	}

	key, err := s.cipher.Decrypt(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("расшифровка приватного ключа: %w", err)
	}

	c.PrivateKey = string(key)
	c.NotAfter = time.Unix(notAfter, 0)

	return &c, nil
}

// CertMeta — то, что известно о сертификате без приватного ключа.
type CertMeta struct {
	Serial   string
	NotAfter time.Time
}

// LatestCertMeta отвечает на вопросы «когда истекает» и «какой серийник»,
// не расшифровывая приватный ключ. Этого хватает планировщику и странице
// статуса, а ключ незачем поднимать в память на каждый тик.
func (s *Store) LatestCertMeta(ctx context.Context, domainID int64) (*CertMeta, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT serial, not_after
		FROM certs WHERE domain_id = ? ORDER BY issued_at DESC, id DESC LIMIT 1`, domainID)

	var (
		m        CertMeta
		notAfter int64
	)

	err := row.Scan(&m.Serial, &notAfter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("чтение сертификата: %w", err)
	}

	m.NotAfter = time.Unix(notAfter, 0)
	return &m, nil
}

// SetClientDomains заменяет весь набор доменов клиента разом: прокси
// присылает желаемое состояние целиком, и домен, из него пропавший,
// перестаёт обслуживаться. Сам домен не удаляется — его учётка acme-dns
// остаётся, поэтому вернуть домен можно без нового CNAME.
func (s *Store) SetClientDomains(ctx context.Context, client string, names []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("начало транзакции: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM domain_clients WHERE client_name = ?`, client); err != nil {
		return fmt.Errorf("снятие доменов клиента %s: %w", client, err)
	}

	for _, name := range names {
		_, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO domain_clients (domain_id, client_name)
			SELECT id, ? FROM domains WHERE name = ?`, client, name)
		if err != nil {
			return fmt.Errorf("привязка домена %s к клиенту %s: %w", name, client, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("фиксация набора доменов клиента %s: %w", client, err)
	}
	return nil
}

// ClientsForDomain — прокси, которые сейчас обслуживают домен.
// Пустой список означает, что домен больше никому не нужен.
func (s *Store) ClientsForDomain(ctx context.Context, domainID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT client_name FROM domain_clients WHERE domain_id = ? ORDER BY client_name`, domainID)
	if err != nil {
		return nil, fmt.Errorf("клиенты домена %d: %w", domainID, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("чтение клиента домена %d: %w", domainID, err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// DomainsForClient — домены, которые сейчас обслуживает прокси.
func (s *Store) DomainsForClient(ctx context.Context, client string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.name FROM domains d
		JOIN domain_clients dc ON dc.domain_id = d.id
		WHERE dc.client_name = ? ORDER BY d.name`, client)
	if err != nil {
		return nil, fmt.Errorf("домены клиента %s: %w", client, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("чтение домена клиента %s: %w", client, err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// SaveClient заводит прокси или заменяет его токен. Замена нужна
// прокси, потерявшему свой том: он возвращается под тем же именем и
// сохраняет привязанные к нему домены.
func (s *Store) SaveClient(ctx context.Context, name, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO clients (name, token_hash, created_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET token_hash = excluded.token_hash`,
		name, tokenHash, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("сохранение клиента %s: %w", name, err)
	}
	return nil
}

// DeleteClient отключает прокси: удаляет токен и снимает с прокси все
// домены. Сами домены остаются вместе с учётками acme-dns — домен,
// который подхватит другой прокси, не потребует нового CNAME.
//
// ErrNotFound означает, что такого прокси в базе нет: отзыв у
// несуществующего имени должен быть заметен, а не выглядеть успехом.
func (s *Store) DeleteClient(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("начало транзакции: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `DELETE FROM clients WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("удаление клиента %s: %w", name, err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("удаление клиента %s: %w", name, err)
	}
	if n == 0 {
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM domain_clients WHERE client_name = ?`, name); err != nil {
		return fmt.Errorf("снятие доменов клиента %s: %w", name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("фиксация отзыва прокси %s: %w", name, err)
	}
	return nil
}

// ClientByTokenHash возвращает имя прокси, предъявившего токен.
func (s *Store) ClientByTokenHash(ctx context.Context, tokenHash string) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT name FROM clients WHERE token_hash = ?`, tokenHash)

	var name string
	err := row.Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("поиск клиента по токену: %w", err)
	}
	return name, nil
}

func (s *Store) SaveACMEAccount(ctx context.Context, a ACMEAccount) error {
	key, err := s.cipher.Encrypt(a.PrivateKeyPEM)
	if err != nil {
		return fmt.Errorf("шифрование ключа ACME-аккаунта: %w", err)
	}

	// Аккаунт создаётся до обращения в ACME, поэтому регистрации может
	// ещё не быть; в БД она хранится пустым значением, а не NULL.
	registration := a.RegistrationJSON
	if registration == nil {
		registration = []byte{}
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO acme_account (id, email, privkey_enc, registration) VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET email = excluded.email,
		                              privkey_enc = excluded.privkey_enc,
		                              registration = excluded.registration`,
		a.Email, key, registration)
	if err != nil {
		return fmt.Errorf("сохранение ACME-аккаунта: %w", err)
	}
	return nil
}

func (s *Store) LoadACMEAccount(ctx context.Context) (*ACMEAccount, error) {
	row := s.db.QueryRowContext(ctx, `SELECT email, privkey_enc, registration FROM acme_account WHERE id = 1`)

	var (
		a      ACMEAccount
		keyEnc []byte
	)

	err := row.Scan(&a.Email, &keyEnc, &a.RegistrationJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("чтение ACME-аккаунта: %w", err)
	}

	key, err := s.cipher.Decrypt(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("расшифровка ключа ACME-аккаунта: %w", err)
	}
	a.PrivateKeyPEM = key

	return &a, nil
}
