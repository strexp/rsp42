package service

import (
	"time"

	"rsp42/internal/kms"
	"rsp42/internal/store"
)

// SessionService persists ES9+/ES11 sessions, encrypting sensitive material at
// rest with the KMS key-encryption key.
type SessionService struct {
	Repo SessionStore
	KMS  kms.Sealer
	TTL  time.Duration
}

// NewSessionService builds a SessionService.
func NewSessionService(repo SessionStore, provider kms.Sealer, ttl time.Duration) *SessionService {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &SessionService{Repo: repo, KMS: provider, TTL: ttl}
}

// Put encrypts sensitive fields and stores the session.
func (s *SessionService) Put(sess *store.Session) error {
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	if sess.ExpiresAt.IsZero() {
		sess.ExpiresAt = sess.CreatedAt.Add(s.TTL)
	}
	enc := []*[]byte{&sess.ServerChallenge, &sess.SmdpOtSK, &sess.SharedSecret, &sess.CCHash}
	for _, f := range enc {
		if len(*f) == 0 {
			continue
		}
		ct, err := s.KMS.Encrypt(*f)
		if err != nil {
			return err
		}
		*f = ct
	}
	return s.Repo.Put(sess)
}

// Get loads and decrypts a session.
func (s *SessionService) Get(txn string) (*store.Session, error) {
	sess, err := s.Repo.Get(txn)
	if err != nil {
		return nil, err
	}
	dec := []*[]byte{&sess.ServerChallenge, &sess.SmdpOtSK, &sess.SharedSecret, &sess.CCHash}
	for _, f := range dec {
		if len(*f) == 0 {
			continue
		}
		pt, err := s.KMS.Decrypt(*f)
		if err != nil {
			return nil, err
		}
		*f = pt
	}
	return sess, nil
}

// Delete removes a session.
func (s *SessionService) Delete(txn string) error { return s.Repo.Delete(txn) }

// GC removes expired sessions.
func (s *SessionService) GC(now time.Time) (int64, error) { return s.Repo.GCExpired(now) }
