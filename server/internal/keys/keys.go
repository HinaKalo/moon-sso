// Package keys manages JWT signing keys: RS256 for ID tokens (OIDC default)
// and ES256 for access tokens. Keys move next → active → retired so that
// verifiers see a new key in the JWKS before anything is signed with it.
package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync/atomic"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	mcrypto "moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
)

const (
	StateNext    = 1
	StateActive  = 2
	StateRetired = 3

	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// PrePublish is how long a new key is published before it signs anything.
// SDKs cache the JWKS for at most one hour and refetch on an unknown kid.
const PrePublish = 24 * time.Hour

// RetiredPublish keeps retired keys in the JWKS until tokens signed with them expire.
const RetiredPublish = 48 * time.Hour

type key struct {
	kid      string
	alg      string
	state    int
	signer   crypto.Signer
	pub      jose.JSONWebKey
	activate time.Time
	retired  *time.Time
}

type snapshot struct {
	active map[string]*key // by alg
	jwks   []byte
	etag   string
	byKID  map[string]*key
}

type Manager struct {
	db     *db.DB
	sealer *mcrypto.Sealer
	log    *slog.Logger
	cur    atomic.Pointer[snapshot]
	now    func() time.Time
}

func NewManager(ctx context.Context, d *db.DB, sealer *mcrypto.Sealer, log *slog.Logger) (*Manager, error) {
	m := &Manager{db: d, sealer: sealer, log: log, now: time.Now}
	if err := m.ensure(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func aad(kid string) []byte { return []byte("sigkey:" + kid) }

func generate(alg string) (crypto.Signer, error) {
	switch alg {
	case AlgRS256:
		return rsa.GenerateKey(rand.Reader, 2048)
	case AlgES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return nil, fmt.Errorf("unsupported alg %s", alg)
}

func (m *Manager) insert(ctx context.Context, q db.Querier, alg string, state int, activate time.Time) error {
	signer, err := generate(alg)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return err
	}
	kid := mcrypto.RandomToken(12)
	pub := jose.JSONWebKey{Key: signer.Public(), KeyID: kid, Algorithm: alg, Use: "sig"}
	pubJSON, err := pub.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `INSERT INTO signing_keys (kid, alg, private_enc, public_jwk, state, created_at, activate_at)
		VALUES (?,?,?,?,?,?,?)`, kid, alg, m.sealer.Seal(der, aad(kid)), pubJSON, state, m.now().UTC(), activate)
	return err
}

// ensure creates an active key for each algorithm if none exists, then loads.
func (m *Manager) ensure(ctx context.Context) error {
	release, err := m.db.Lock(ctx, "signing-keys", 10*time.Second)
	if err != nil {
		return err
	}
	defer release()
	for _, alg := range []string{AlgRS256, AlgES256} {
		var n int
		if err := m.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM signing_keys WHERE alg=? AND state=?", alg, StateActive).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if err := m.insert(ctx, m.db, alg, StateActive, m.now().UTC()); err != nil {
				return err
			}
			m.log.Info("created signing key", "alg", alg)
		}
	}
	return m.load(ctx)
}

func (m *Manager) load(ctx context.Context) error {
	rows, err := m.db.QueryContext(ctx, "SELECT kid, alg, private_enc, public_jwk, state, activate_at, retired_at FROM signing_keys WHERE state IN (1,2,3)")
	if err != nil {
		return err
	}
	defer rows.Close()
	s := &snapshot{active: map[string]*key{}, byKID: map[string]*key{}}
	now := m.now()
	var pubs []jose.JSONWebKey
	for rows.Next() {
		var k key
		var enc, pubJSON []byte
		var retired sql.NullTime
		if err := rows.Scan(&k.kid, &k.alg, &enc, &pubJSON, &k.state, &k.activate, &retired); err != nil {
			return err
		}
		if retired.Valid {
			t := retired.Time
			k.retired = &t
			if now.Sub(t) > RetiredPublish {
				continue
			}
		}
		der, err := m.sealer.Open(enc, aad(k.kid))
		if err != nil {
			return fmt.Errorf("signing key %s: %w", k.kid, err)
		}
		priv, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		k.signer = priv.(crypto.Signer)
		if err := k.pub.UnmarshalJSON(pubJSON); err != nil {
			return err
		}
		kk := k
		s.byKID[k.kid] = &kk
		pubs = append(pubs, k.pub)
		if k.state == StateActive {
			if prev, ok := s.active[k.alg]; !ok || k.activate.After(prev.activate) {
				s.active[k.alg] = &kk
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, alg := range []string{AlgRS256, AlgES256} {
		if s.active[alg] == nil {
			return fmt.Errorf("no active %s signing key", alg)
		}
	}
	jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: pubs})
	if err != nil {
		return err
	}
	s.jwks = jwks
	sum := sha256.Sum256(jwks)
	s.etag = `"` + hex.EncodeToString(sum[:8]) + `"`
	m.cur.Store(s)
	return nil
}

// Rotate publishes a new key per algorithm; it becomes active after PrePublish.
func (m *Manager) Rotate(ctx context.Context) error {
	release, err := m.db.Lock(ctx, "signing-keys", 10*time.Second)
	if err != nil {
		return err
	}
	defer release()
	act := m.now().UTC().Add(PrePublish)
	err = m.db.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		for _, alg := range []string{AlgRS256, AlgES256} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM signing_keys WHERE alg=? AND state=?", alg, StateNext); err != nil {
				return err
			}
			if err := m.insert(ctx, tx, alg, StateNext, act); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return m.load(ctx)
}

// promote activates due "next" keys and retires the keys they replace.
func (m *Manager) promote(ctx context.Context) error {
	release, err := m.db.Lock(ctx, "signing-keys", 5*time.Second)
	if err != nil {
		return err
	}
	defer release()
	now := m.now().UTC()
	return m.db.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT kid, alg FROM signing_keys WHERE state=? AND activate_at <= ?", StateNext, now)
		if err != nil {
			return err
		}
		type due struct{ kid, alg string }
		var list []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.kid, &d.alg); err != nil {
				rows.Close()
				return err
			}
			list = append(list, d)
		}
		rows.Close()
		for _, d := range list {
			if _, err := tx.ExecContext(ctx, "UPDATE signing_keys SET state=?, retired_at=? WHERE alg=? AND state=?", StateRetired, now, d.alg, StateActive); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE signing_keys SET state=? WHERE kid=?", StateActive, d.kid); err != nil {
				return err
			}
			m.log.Info("signing key activated", "kid", d.kid, "alg", d.alg)
		}
		_, err = tx.ExecContext(ctx, "DELETE FROM signing_keys WHERE state=? AND retired_at < ?", StateRetired, now.Add(-30*24*time.Hour))
		return err
	})
}

// Run promotes keys and reloads the key set periodically.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.promote(ctx); err != nil && !errors.Is(err, db.ErrLockBusy) && ctx.Err() == nil {
				m.log.Warn("key promotion failed", "err", err)
			}
			if err := m.load(ctx); err != nil && ctx.Err() == nil {
				m.log.Error("key reload failed", "err", err)
			}
		}
	}
}

// JWKS returns the published key set and its ETag.
func (m *Manager) JWKS() ([]byte, string) {
	s := m.cur.Load()
	return s.jwks, s.etag
}

// Public returns the public key for kid (used to verify our own tokens).
func (m *Manager) Public(kid string) (crypto.PublicKey, string, bool) {
	k, ok := m.cur.Load().byKID[kid]
	if !ok {
		return nil, "", false
	}
	return k.signer.Public(), k.alg, true
}

var b64 = base64.RawURLEncoding

// Sign produces a compact JWS of claims with the active key for alg.
func (m *Manager) Sign(alg, typ string, claims any) (string, error) {
	k := m.cur.Load().active[alg]
	if k == nil {
		return "", fmt.Errorf("no active key for %s", alg)
	}
	hdr := map[string]string{"alg": alg, "kid": k.kid}
	if typ != "" {
		hdr["typ"] = typ
	}
	hb, _ := json.Marshal(hdr)
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := make([]byte, 0, b64.EncodedLen(len(hb))+1+b64.EncodedLen(len(pb)))
	input = b64.AppendEncode(input, hb)
	input = append(input, '.')
	input = b64.AppendEncode(input, pb)
	digest := sha256.Sum256(input)
	var sig []byte
	switch alg {
	case AlgRS256:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.signer.(*rsa.PrivateKey), crypto.SHA256, digest[:])
	case AlgES256:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k.signer.(*ecdsa.PrivateKey), digest[:])
		if err == nil {
			sig = make([]byte, 64)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
		}
	}
	if err != nil {
		return "", err
	}
	out := append(input, '.')
	return string(b64.AppendEncode(out, sig)), nil
}

// Verify checks a compact JWS signed by one of our keys and returns the payload.
func (m *Manager) Verify(token string, wantTyp string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("unexpected signatures")
	}
	h := jws.Signatures[0].Header
	pub, alg, ok := m.Public(h.KeyID)
	if !ok || alg != h.Algorithm {
		return nil, errors.New("unknown signing key")
	}
	if wantTyp != "" {
		if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != wantTyp {
			return nil, errors.New("unexpected token type")
		}
	}
	return jws.Verify(pub)
}

// List returns key metadata for the admin panel.
type Info struct {
	KID      string
	Alg      string
	State    int
	Activate time.Time
	Retired  *time.Time
}

func (m *Manager) List(ctx context.Context) ([]Info, error) {
	rows, err := m.db.QueryContext(ctx, "SELECT kid, alg, state, activate_at, retired_at FROM signing_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Info
	for rows.Next() {
		var i Info
		var r sql.NullTime
		if err := rows.Scan(&i.KID, &i.Alg, &i.State, &i.Activate, &r); err != nil {
			return nil, err
		}
		if r.Valid {
			t := r.Time
			i.Retired = &t
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
