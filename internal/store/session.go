package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// marshalStrings renders a string slice as a JSON array for a TEXT column; an
// empty slice is stored as NULL.
func marshalStrings(v []string) string {
	if len(v) == 0 {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// unmarshalStrings parses a JSON array written by marshalStrings.
func unmarshalStrings(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

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
	UPPTemplate     string
	// EuiccProfileVersion is the base SAIP version the eUICC advertised
	// (SGP.22 §5.7.6 profileVersion), canonical "<major>.<minor>" (N11).
	EuiccProfileVersion string
	// EuiccSupportedVersions lists profileVersion plus every entry of
	// additionalEuiccProfilePackageVersions, canonical "<major>.<minor>".
	EuiccSupportedVersions []string
	// UICCCapability is the raw uiccCapability BIT STRING content, hex encoded.
	UICCCapability string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// Put inserts or replaces a session.
func (r *SessionRepo) Put(s *Session) error {
	_, err := r.db.Exec(`INSERT INTO sessions
		(transaction_id, state, server_challenge, server_signed1, smdp_signature2, ci_cert_id, eid, euicc_cert, eum_cert,
		 euicc_otpk, smdp_ot_sk, host_id, shared_secret, profile_id, cc_hash, cc_required, upp_template,
		 euicc_profile_version, euicc_supported_versions, uicc_capability, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(transaction_id) DO UPDATE SET
		 state=excluded.state, server_challenge=excluded.server_challenge, server_signed1=excluded.server_signed1,
		 smdp_signature2=excluded.smdp_signature2,
		 ci_cert_id=excluded.ci_cert_id, eid=excluded.eid, euicc_cert=excluded.euicc_cert, eum_cert=excluded.eum_cert,
		 euicc_otpk=excluded.euicc_otpk, smdp_ot_sk=excluded.smdp_ot_sk, host_id=excluded.host_id,
		 shared_secret=excluded.shared_secret, profile_id=excluded.profile_id, cc_hash=excluded.cc_hash,
		 cc_required=excluded.cc_required, upp_template=excluded.upp_template,
		 euicc_profile_version=excluded.euicc_profile_version,
		 euicc_supported_versions=excluded.euicc_supported_versions, uicc_capability=excluded.uicc_capability,
		 expires_at=excluded.expires_at`,
		s.TransactionID, s.State, s.ServerChallenge, s.ServerSigned1, s.SmdpSignature2, s.CICertID, nullStr(s.EID), s.EuiccCert, s.EumCert,
		s.EuiccOtpk, s.SmdpOtSK, s.HostID, s.SharedSecret, s.ProfileID, s.CCHash, boolInt(s.CCRequired), nullStr(s.UPPTemplate),
		nullStr(s.EuiccProfileVersion), nullStr(marshalStrings(s.EuiccSupportedVersions)), nullStr(s.UICCCapability),
		s.CreatedAt.Unix(), s.ExpiresAt.Unix())
	return err
}

// sessionCols is the canonical session column list.
const sessionCols = `transaction_id, state, server_challenge, server_signed1, smdp_signature2, ci_cert_id, eid,
	euicc_cert, eum_cert, euicc_otpk, smdp_ot_sk, host_id, shared_secret, profile_id, cc_hash, cc_required, upp_template,
	euicc_profile_version, euicc_supported_versions, uicc_capability, created_at, expires_at`

func scanSession(sc rowScanner) (*Session, error) {
	var s Session
	var eid, uppTpl, profileVer, supported, uiccCap sql.NullString
	var ccReq int
	var created, expires int64
	if err := sc.Scan(&s.TransactionID, &s.State, &s.ServerChallenge, &s.ServerSigned1, &s.SmdpSignature2, &s.CICertID, &eid,
		&s.EuiccCert, &s.EumCert, &s.EuiccOtpk, &s.SmdpOtSK, &s.HostID, &s.SharedSecret, &s.ProfileID, &s.CCHash,
		&ccReq, &uppTpl, &profileVer, &supported, &uiccCap, &created, &expires); err != nil {
		return nil, err
	}
	s.EID = eid.String
	s.UPPTemplate = uppTpl.String
	s.EuiccProfileVersion = profileVer.String
	s.EuiccSupportedVersions = unmarshalStrings(supported.String)
	s.UICCCapability = uiccCap.String
	s.CCRequired = ccReq != 0
	s.CreatedAt = toTime(created)
	s.ExpiresAt = toTime(expires)
	return &s, nil
}

// Get loads a session by transaction id.
func (r *SessionRepo) Get(txn string) (*Session, error) {
	row := r.db.QueryRow(`SELECT `+sessionCols+` FROM sessions WHERE transaction_id = ?`, txn)
	s, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
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

// ListByProfileID returns the download sessions attached to a profile, newest
// first (used by the profile timeline).
func (r *SessionRepo) ListByProfileID(profileID int64) ([]*Session, error) {
	rows, err := r.db.Query(`SELECT `+sessionCols+` FROM sessions WHERE profile_id = ? ORDER BY created_at DESC`, profileID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
