package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProfileRepo persists the SM-DP+ profile inventory.
type ProfileRepo struct{ db *sql.DB }

const profileCols = `id, tenant_id, external_ref, iccid, imsi, profile_type, eid, state, matching_id, cc_hash, cc_required,
	smds_address, release_flag, download_attempts, cc_attempts, upp_template, ppr_ids, personalization,
	created_at, updated_at, installed_at, error_reason, batch_id`

func scanProfile(sc rowScanner) (*Profile, error) {
	var p Profile
	var tenant, extRef, imsi, ptype, eid, matching, smds, upp, pers, errReason sql.NullString
	var ccHash, pprIds []byte
	var ccReq, relFlag int
	var created, updated int64
	var installed, batchID sql.NullInt64
	if err := sc.Scan(&p.ID, &tenant, &extRef, &p.ICCID, &imsi, &ptype, &eid, &p.State, &matching, &ccHash, &ccReq,
		&smds, &relFlag, &p.DownloadAttempts, &p.CCAttempts, &upp, &pprIds, &pers, &created, &updated, &installed, &errReason, &batchID); err != nil {
		return nil, err
	}
	if batchID.Valid {
		v := batchID.Int64
		p.BatchID = &v
	}
	p.TenantID = tenant.String
	p.ExternalRef = extRef.String
	p.IMSI = imsi.String
	p.ProfileType = ptype.String
	p.EID = eid.String
	p.MatchingID = matching.String
	p.SMDSAddress = smds.String
	p.UPPTemplate = upp.String
	p.PPRIds = pprIds
	p.Personalization = pers.String
	p.ErrorReason = errReason.String
	p.CCHash = ccHash
	p.CCRequired = ccReq != 0
	p.ReleaseFlag = relFlag != 0
	p.CreatedAt = toTime(created)
	p.UpdatedAt = toTime(updated)
	if installed.Valid {
		t := toTime(installed.Int64)
		p.InstalledAt = &t
	}
	return &p, nil
}

// Create inserts a profile and returns its id.
func (r *ProfileRepo) Create(p *Profile) (int64, error) {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	p.UpdatedAt = p.CreatedAt
	now := p.CreatedAt.Unix()
	res, err := r.db.Exec(`INSERT INTO profiles
		(tenant_id, external_ref, iccid, imsi, profile_type, eid, state, matching_id, cc_hash, cc_required, smds_address,
		 release_flag, download_attempts, cc_attempts, upp_template, ppr_ids, personalization,
		 created_at, updated_at, error_reason, batch_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		nullStr(p.TenantID), nullStr(p.ExternalRef), p.ICCID, nullStr(p.IMSI), nullStr(p.ProfileType), nullStr(p.EID), string(p.State), nullStr(p.MatchingID),
		p.CCHash, boolInt(p.CCRequired), nullStr(p.SMDSAddress), boolInt(p.ReleaseFlag),
		p.DownloadAttempts, p.CCAttempts, nullStr(p.UPPTemplate), p.PPRIds, nullStr(p.Personalization), now, now, nullStr(p.ErrorReason), p.BatchID)
	if err != nil {
		return 0, fmt.Errorf("store: create profile: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	p.ID = id
	return id, nil
}

// GetByICCID loads a profile by ICCID.
func (r *ProfileRepo) GetByICCID(iccid string) (*Profile, error) {
	return r.getOne("SELECT "+profileCols+" FROM profiles WHERE iccid = ?", iccid)
}

// GetByMatchingID loads a profile by matching id.
func (r *ProfileRepo) GetByMatchingID(matchingID string) (*Profile, error) {
	return r.getOne("SELECT "+profileCols+" FROM profiles WHERE matching_id = ?", matchingID)
}

// GetByID loads a profile by id.
func (r *ProfileRepo) GetByID(id int64) (*Profile, error) {
	return r.getOne("SELECT "+profileCols+" FROM profiles WHERE id = ?", id)
}

func (r *ProfileRepo) getOne(query string, arg any) (*Profile, error) {
	row := r.db.QueryRow(query, arg)
	p, err := scanProfile(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// List returns all profiles ordered by creation time.
func (r *ProfileRepo) List() ([]*Profile, error) {
	rows, err := r.db.Query("SELECT " + profileCols + " FROM profiles ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Profile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProfileFilter constrains a profile listing (all fields optional).
type ProfileFilter struct {
	// Tenant matches an exact tenant id. A non-nil pointer to "" selects the
	// platform-default profiles (tenant_id IS NULL); nil means "any tenant".
	Tenant      *string
	ExternalRef string     // exact external reference
	State       string     // exact state
	EID         string     // exact EID
	ICCID       string     // ICCID prefix
	Query       string     // substring over iccid/imsi/eid/matching_id
	BatchID     *int64     // profiles belonging to a download batch
	Since       *time.Time // created_at >= Since
	Until       *time.Time // created_at <= Until
}

// ListFiltered returns a page of profiles and the total matching count. sort is
// one of "created_at", "updated_at", "iccid", "state" (optionally prefixed with
// '-'); anything else falls back to newest-first by created_at.
func (r *ProfileRepo) ListFiltered(f ProfileFilter, limit, offset int, sort string) ([]*Profile, int, error) {
	where, args := profileWhere(f)
	clause := buildWhere(where)

	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM profiles"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Query("SELECT "+profileCols+" FROM profiles"+clause+profileOrder(sort)+" LIMIT ? OFFSET ?",
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Profile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// profileWhere builds the WHERE conditions for a profile filter.
func profileWhere(f ProfileFilter) ([]string, []any) {
	var where []string
	var args []any
	if f.Tenant != nil {
		if *f.Tenant == "" {
			where = append(where, "tenant_id IS NULL")
		} else {
			where, args = append(where, "tenant_id = ?"), append(args, *f.Tenant)
		}
	}
	if f.ExternalRef != "" {
		where, args = append(where, "external_ref = ?"), append(args, f.ExternalRef)
	}
	if f.State != "" {
		where, args = append(where, "state = ?"), append(args, f.State)
	}
	if f.EID != "" {
		where, args = append(where, "eid = ?"), append(args, f.EID)
	}
	if f.ICCID != "" {
		where, args = append(where, "iccid LIKE ?"), append(args, f.ICCID+"%")
	}
	if f.Query != "" {
		where = append(where, "(iccid LIKE ? OR imsi LIKE ? OR eid LIKE ? OR matching_id LIKE ?)")
		q := "%" + f.Query + "%"
		args = append(args, q, q, q, q)
	}
	if f.BatchID != nil {
		where, args = append(where, "batch_id = ?"), append(args, *f.BatchID)
	}
	if f.Since != nil {
		where, args = append(where, "created_at >= ?"), append(args, f.Since.Unix())
	}
	if f.Until != nil {
		where, args = append(where, "created_at <= ?"), append(args, f.Until.Unix())
	}
	return where, args
}

func profileOrder(sort string) string {
	dir := "DESC"
	col := "created_at"
	if strings.HasPrefix(sort, "-") {
		dir, sort = "ASC", sort[1:]
	}
	switch sort {
	// "tenant" sorts by the platform-default-normalised owner so NULL rows
	// order consistently with the API contract (N7).
	case "created_at", "updated_at", "iccid", "state", "installed_at":
		col = sort
	case "tenant":
		col = "COALESCE(tenant_id,'')"
	case "":
	default:
		return " ORDER BY created_at DESC"
	}
	return " ORDER BY " + col + " " + dir
}

// Update writes all mutable fields of p.
func (r *ProfileRepo) Update(p *Profile) error {
	p.UpdatedAt = time.Now().UTC()
	_, err := r.db.Exec(`UPDATE profiles SET
		tenant_id=?, external_ref=?, imsi=?, profile_type=?, eid=?, state=?, matching_id=?, cc_hash=?, cc_required=?, smds_address=?,
		release_flag=?, download_attempts=?, cc_attempts=?, upp_template=?, ppr_ids=?, personalization=?,
		updated_at=?, installed_at=?, error_reason=?, batch_id=? WHERE id=?`,
		nullStr(p.TenantID), nullStr(p.ExternalRef), nullStr(p.IMSI), nullStr(p.ProfileType), nullStr(p.EID), string(p.State), nullStr(p.MatchingID),
		p.CCHash, boolInt(p.CCRequired), nullStr(p.SMDSAddress), boolInt(p.ReleaseFlag),
		p.DownloadAttempts, p.CCAttempts, nullStr(p.UPPTemplate), p.PPRIds, nullStr(p.Personalization),
		p.UpdatedAt.Unix(), nullTime(p.InstalledAt), nullStr(p.ErrorReason), p.BatchID, p.ID)
	if err != nil {
		return fmt.Errorf("store: update profile: %w", err)
	}
	return nil
}

// Delete removes a profile by ICCID.
func (r *ProfileRepo) Delete(iccid string) error {
	_, err := r.db.Exec("DELETE FROM profiles WHERE iccid = ?", iccid)
	return err
}

// EIDSummary aggregates the profiles installed on one eUICC.
type EIDSummary struct {
	EID            string    `json:"eid"`
	ProfileCount   int       `json:"profileCount"`
	InstalledCount int       `json:"installedCount"`
	LastUpdatedAt  time.Time `json:"lastUpdatedAt"`
}

// ListEIDs returns one row per EID seen in the inventory, ordered by EID.
func (r *ProfileRepo) ListEIDs(f ProfileFilter, limit, offset int) ([]EIDSummary, int, error) {
	where, args := profileWhere(f)
	where = append(where, "eid IS NOT NULL", "eid <> ''")
	clause := buildWhere(where)

	var total int
	if err := r.db.QueryRow("SELECT COUNT(DISTINCT eid) FROM profiles"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(`SELECT eid, COUNT(*), SUM(CASE WHEN state = 'Installed' THEN 1 ELSE 0 END), MAX(updated_at)
		FROM profiles`+clause+` GROUP BY eid ORDER BY eid LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []EIDSummary
	for rows.Next() {
		var e EIDSummary
		var installed sql.NullInt64
		var updated sql.NullInt64
		if err := rows.Scan(&e.EID, &e.ProfileCount, &installed, &updated); err != nil {
			return nil, 0, err
		}
		e.InstalledCount = int(installed.Int64)
		if updated.Valid {
			e.LastUpdatedAt = toTime(updated.Int64)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

var profileGroupBy = map[string]string{
	"state":        "state",
	"tenant":       "COALESCE(tenant_id,'')",
	"profile_type": "COALESCE(profile_type,'')",
	"day":          "strftime('%Y-%m-%d', created_at, 'unixepoch')",
}

// Stats returns profile counts grouped by groupBy ("state" by default).
func (r *ProfileRepo) Stats(f ProfileFilter, groupBy string) ([]StatCount, error) {
	expr, err := statGroupBy(groupBy, profileGroupBy, "state")
	if err != nil {
		return nil, err
	}
	conds, args := profileWhere(f)
	rows, err := r.db.Query(`SELECT `+expr+` AS k, COUNT(*) FROM profiles`+buildWhere(conds)+
		` GROUP BY k ORDER BY COUNT(*) DESC, k ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []StatCount{}
	for rows.Next() {
		var sc StatCount
		if err := rows.Scan(&sc.Key, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ProfileState is the SGP.22 profile lifecycle state (SGP.22 §3.1.6 Table 6b).
type ProfileState string

// Profile states.
const (
	StateAvailable   ProfileState = "Available"
	StateAllocated   ProfileState = "Allocated"
	StateLinked      ProfileState = "Linked"
	StateConfirmed   ProfileState = "Confirmed"
	StateReleased    ProfileState = "Released"
	StateDownloaded  ProfileState = "Downloaded"
	StateInstalled   ProfileState = "Installed"
	StateError       ProfileState = "Error"
	StateUnavailable ProfileState = "Unavailable"
)

// Profile is a row of the profile inventory.
type Profile struct {
	ID int64
	// TenantID is the owning carrier; the empty string is the platform default.
	TenantID string
	// ExternalRef is the caller's own identifier for this profile. It is an
	// Admin API convenience field only and is never carried on ES2+.
	ExternalRef string
	ICCID       string
	IMSI        string
	ProfileType string
	EID         string
	State       ProfileState
	MatchingID  string
	// CCHash is SHA-256 of the operator-supplied confirmation code, stored as a
	// plain digest; confirmationHash() mixes it with the TransactionID. It is
	// not encrypted at rest (only Session secrets are).
	CCHash           []byte
	CCRequired       bool
	SMDSAddress      string
	ReleaseFlag      bool
	DownloadAttempts int
	CCAttempts       int
	UPPTemplate      string
	PPRIds           []byte // PprIds BIT STRING content bytes
	BatchID          *int64
	Personalization  string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	InstalledAt      *time.Time
	ErrorReason      string
}

// ProfileName returns a human-readable profile name for metadata.
func (p *Profile) ProfileName() string {
	if p.UPPTemplate != "" {
		return p.UPPTemplate
	}
	return "RSP42 Profile " + p.ICCID
}
