package store

import (
	"database/sql"
	"errors"
	"time"
)

// SessionRepo persists ES9+/ES11 RSP sessions.
type SessionRepo struct{ db *sql.DB }

// Session is a persisted RSP session.
type Session struct {
	TransactionID   string
	State           string
	ServerChallenge []byte
	ServerSigned1   []byte
	SmdpSignature2  []byte
	CICertID        []byte
	EID             string
	EuiccCert       []byte
	EumCert         []byte
	EuiccOtpk       []byte
	SmdpOtSK        []byte // encrypted
	HostID          []byte
	SharedSecret    []byte // encrypted
	ProfileID       int64
	CCHash          []byte
	CCRequired      bool
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// Put inserts or replaces a session.
func (r *SessionRepo) Put(s *Session) error {
	_, err := r.db.Exec(`INSERT INTO sessions
		(transaction_id, state, server_challenge, server_signed1, smdp_signature2, ci_cert_id, eid, euicc_cert, eum_cert,
		 euicc_otpk, smdp_ot_sk, host_id, shared_secret, profile_id, cc_hash, cc_required, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(transaction_id) DO UPDATE SET
		 state=excluded.state, server_challenge=excluded.server_challenge, server_signed1=excluded.server_signed1,
		 smdp_signature2=excluded.smdp_signature2,
		 ci_cert_id=excluded.ci_cert_id, eid=excluded.eid, euicc_cert=excluded.euicc_cert, eum_cert=excluded.eum_cert,
		 euicc_otpk=excluded.euicc_otpk, smdp_ot_sk=excluded.smdp_ot_sk, host_id=excluded.host_id,
		 shared_secret=excluded.shared_secret, profile_id=excluded.profile_id, cc_hash=excluded.cc_hash,
		 cc_required=excluded.cc_required, expires_at=excluded.expires_at`,
		s.TransactionID, s.State, s.ServerChallenge, s.ServerSigned1, s.SmdpSignature2, s.CICertID, nullStr(s.EID), s.EuiccCert, s.EumCert,
		s.EuiccOtpk, s.SmdpOtSK, s.HostID, s.SharedSecret, s.ProfileID, s.CCHash, boolInt(s.CCRequired),
		s.CreatedAt.Unix(), s.ExpiresAt.Unix())
	return err
}

// Get loads a session by transaction id.
func (r *SessionRepo) Get(txn string) (*Session, error) {
	row := r.db.QueryRow(`SELECT transaction_id, state, server_challenge, server_signed1, smdp_signature2, ci_cert_id, eid,
		euicc_cert, eum_cert, euicc_otpk, smdp_ot_sk, host_id, shared_secret, profile_id, cc_hash, cc_required,
		created_at, expires_at FROM sessions WHERE transaction_id = ?`, txn)
	var s Session
	var eid sql.NullString
	var ccReq int
	var created, expires int64
	err := row.Scan(&s.TransactionID, &s.State, &s.ServerChallenge, &s.ServerSigned1, &s.SmdpSignature2, &s.CICertID, &eid,
		&s.EuiccCert, &s.EumCert, &s.EuiccOtpk, &s.SmdpOtSK, &s.HostID, &s.SharedSecret, &s.ProfileID, &s.CCHash,
		&ccReq, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.EID = eid.String
	s.CCRequired = ccReq != 0
	s.CreatedAt = toTime(created)
	s.ExpiresAt = toTime(expires)
	return &s, nil
}

// Delete removes a session.
func (r *SessionRepo) Delete(txn string) error {
	_, err := r.db.Exec("DELETE FROM sessions WHERE transaction_id = ?", txn)
	return err
}

// GCExpired deletes sessions whose expiry is before now and returns the count.
func (r *SessionRepo) GCExpired(now time.Time) (int64, error) {
	res, err := r.db.Exec("DELETE FROM sessions WHERE expires_at < ?", now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListTransactions returns all session transaction ids.
func (r *SessionRepo) ListTransactions() ([]string, error) {
	rows, err := r.db.Query("SELECT transaction_id FROM sessions")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
