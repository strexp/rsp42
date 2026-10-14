package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ProfileRepo persists the SM-DP+ profile inventory.
type ProfileRepo struct{ db *sql.DB }

const profileCols = `id, iccid, imsi, profile_type, eid, state, matching_id, cc_hash, cc_required,
	smds_address, release_flag, download_attempts, cc_attempts, upp_template, ppr_ids, personalization,
	created_at, updated_at, installed_at, error_reason`

func scanProfile(sc interface {
	Scan(dest ...any) error
}) (*Profile, error) {
	var p Profile
	var imsi, ptype, eid, matching, smds, upp, pers, errReason sql.NullString
	var ccHash, pprIds []byte
	var ccReq, relFlag int
	var created, updated int64
	var installed sql.NullInt64
	if err := sc.Scan(&p.ID, &p.ICCID, &imsi, &ptype, &eid, &p.State, &matching, &ccHash, &ccReq,
		&smds, &relFlag, &p.DownloadAttempts, &p.CCAttempts, &upp, &pprIds, &pers, &created, &updated, &installed, &errReason); err != nil {
		return nil, err
	}
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
		(iccid, imsi, profile_type, eid, state, matching_id, cc_hash, cc_required, smds_address,
		 release_flag, download_attempts, cc_attempts, upp_template, ppr_ids, personalization,
		 created_at, updated_at, error_reason)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ICCID, nullStr(p.IMSI), nullStr(p.ProfileType), nullStr(p.EID), string(p.State), nullStr(p.MatchingID),
		p.CCHash, boolInt(p.CCRequired), nullStr(p.SMDSAddress), boolInt(p.ReleaseFlag),
		p.DownloadAttempts, p.CCAttempts, nullStr(p.UPPTemplate), p.PPRIds, nullStr(p.Personalization), now, now, nullStr(p.ErrorReason))
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

// Update writes all mutable fields of p.
func (r *ProfileRepo) Update(p *Profile) error {
	p.UpdatedAt = time.Now().UTC()
	_, err := r.db.Exec(`UPDATE profiles SET
		imsi=?, profile_type=?, eid=?, state=?, matching_id=?, cc_hash=?, cc_required=?, smds_address=?,
		release_flag=?, download_attempts=?, cc_attempts=?, upp_template=?, ppr_ids=?, personalization=?,
		updated_at=?, installed_at=?, error_reason=? WHERE id=?`,
		nullStr(p.IMSI), nullStr(p.ProfileType), nullStr(p.EID), string(p.State), nullStr(p.MatchingID),
		p.CCHash, boolInt(p.CCRequired), nullStr(p.SMDSAddress), boolInt(p.ReleaseFlag),
		p.DownloadAttempts, p.CCAttempts, nullStr(p.UPPTemplate), p.PPRIds, nullStr(p.Personalization),
		p.UpdatedAt.Unix(), nullTime(p.InstalledAt), nullStr(p.ErrorReason), p.ID)
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
