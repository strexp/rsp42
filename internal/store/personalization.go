package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Personalization is a row of the per-ICCID (or credentials-pool) table. K and
// OPc are stored encrypted (the service layer encrypts/decrypts them).
type Personalization struct {
	ID             int64
	TenantID       string
	ICCID          string // empty for a credentials-pool entry
	IMSI           string
	K              []byte
	OPc            []byte
	PIN1           string
	PUK1           string
	ADM1           string
	ADM2           string
	SPN            string
	Algorithm      string
	Rotation       []byte
	Xoring         []byte
	NumberOfKeccak *int64
	// PLMN is a JSON array of {mcc,mnc,act} records.
	PLMN   string
	MSISDN string
	ACC    *int64
	// FilePatches is a JSON array of {fid,hex} raw EF overrides.
	FilePatches string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PersonalizationRepo persists personalization rows. Rows with an ICCID are
// bound to that ICCID; rows without one form the tenant's credentials pool,
// keyed by IMSI.
type PersonalizationRepo struct{ db *sql.DB }

const personalizationCols = `id, COALESCE(tenant_id,''), COALESCE(iccid,''), COALESCE(imsi,''), k, opc,
	pin1, puk1, adm1, adm2, spn, algorithm, rotation, xoring, number_of_keccak,
	plmn, msisdn, acc, file_patches, created_at, updated_at`

func scanPersonalization(sc rowScanner) (*Personalization, error) {
	var p Personalization
	var pin1, puk1, adm1, adm2, spn, algo, plmn, msisdn, patches sql.NullString
	var keccak, acc sql.NullInt64
	var created, updated int64
	if err := sc.Scan(&p.ID, &p.TenantID, &p.ICCID, &p.IMSI, &p.K, &p.OPc,
		&pin1, &puk1, &adm1, &adm2, &spn, &algo, &p.Rotation, &p.Xoring, &keccak,
		&plmn, &msisdn, &acc, &patches, &created, &updated); err != nil {
		return nil, err
	}
	p.PIN1, p.PUK1, p.ADM1, p.ADM2, p.SPN, p.Algorithm =
		pin1.String, puk1.String, adm1.String, adm2.String, spn.String, algo.String
	p.PLMN, p.MSISDN, p.FilePatches = plmn.String, msisdn.String, patches.String
	if keccak.Valid {
		v := keccak.Int64
		p.NumberOfKeccak = &v
	}
	if acc.Valid {
		v := acc.Int64
		p.ACC = &v
	}
	p.CreatedAt, p.UpdatedAt = toTime(created), toTime(updated)
	return &p, nil
}

const personalizationUpdate = `UPDATE personalization SET
	 imsi=?, k=?, opc=?, pin1=?, puk1=?, adm1=?, adm2=?, spn=?, algorithm=?,
	 rotation=?, xoring=?, number_of_keccak=?, plmn=?, msisdn=?, acc=?, file_patches=?, updated_at=?
	 WHERE id = ?`

// Upsert inserts or replaces a row. A row with an ICCID is keyed by
// (tenant, iccid); a credentials-pool row (no ICCID) is keyed by (tenant, imsi).
// The lookup-then-write runs in one transaction so two concurrent upserts
// cannot both decide to insert and violate the tenant-scoped unique index.
func (r *PersonalizationRepo) Upsert(p *Personalization) error {
	return withTx(r.db, func(tx *sql.Tx) error { return upsertPersonalization(tx, p) })
}

// upsertPersonalization is Upsert's body, usable inside a transaction.
func upsertPersonalization(db dbtx, p *Personalization) error {
	now := time.Now().UTC().Unix()
	created := now
	if !p.CreatedAt.IsZero() {
		created = p.CreatedAt.Unix()
	}
	existing, err := lookupPersonalization(db, p.TenantID, p.ICCID, p.IMSI)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if existing != nil {
		_, err := db.Exec(personalizationUpdate,
			nullStr(p.IMSI), p.K, p.OPc, nullStr(p.PIN1), nullStr(p.PUK1), nullStr(p.ADM1), nullStr(p.ADM2),
			nullStr(p.SPN), nullStr(p.Algorithm), p.Rotation, p.Xoring, p.NumberOfKeccak,
			nullStr(p.PLMN), nullStr(p.MSISDN), p.ACC, nullStr(p.FilePatches), now, existing.ID)
		if err != nil {
			return err
		}
		p.ID = existing.ID
		p.CreatedAt = existing.CreatedAt
		p.UpdatedAt = toTime(now)
		return nil
	}
	res, err := db.Exec(`INSERT INTO personalization
		(tenant_id, iccid, imsi, k, opc, pin1, puk1, adm1, adm2, spn, algorithm, rotation, xoring,
		 number_of_keccak, plmn, msisdn, acc, file_patches, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		nullStr(p.TenantID), nullStr(p.ICCID), nullStr(p.IMSI), p.K, p.OPc,
		nullStr(p.PIN1), nullStr(p.PUK1), nullStr(p.ADM1), nullStr(p.ADM2), nullStr(p.SPN), nullStr(p.Algorithm),
		p.Rotation, p.Xoring, p.NumberOfKeccak, nullStr(p.PLMN), nullStr(p.MSISDN), p.ACC, nullStr(p.FilePatches),
		created, now)
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	p.CreatedAt, p.UpdatedAt = toTime(created), toTime(now)
	return nil
}

// lookupPersonalization finds a row by ICCID when set, otherwise by IMSI within
// the tenant. It takes the transaction handle so Upsert can run it read-then-write.
func lookupPersonalization(db dbtx, tenant, iccid, imsi string) (*Personalization, error) {
	query := "SELECT " + personalizationCols + " FROM personalization WHERE COALESCE(tenant_id,'') = ?"
	args := []any{tenant}
	switch {
	case iccid != "":
		query += " AND iccid = ?"
		args = append(args, iccid)
	case imsi != "":
		query += " AND iccid IS NULL AND imsi = ?"
		args = append(args, imsi)
	default:
		return nil, ErrNotFound
	}
	row := db.QueryRow(query, args...)
	p, err := scanPersonalization(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

// GetByICCID loads a personalization row bound to an ICCID.
func (r *PersonalizationRepo) GetByICCID(tenant, iccid string) (*Personalization, error) {
	row := r.db.QueryRow("SELECT "+personalizationCols+
		" FROM personalization WHERE COALESCE(tenant_id,'') = ? AND iccid = ?", tenant, iccid)
	p, err := scanPersonalization(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: personalization %q: %w", iccid, ErrNotFound)
	}
	return p, err
}

// GetByIMSI loads a personalization row by IMSI within a tenant.
func (r *PersonalizationRepo) GetByIMSI(tenant, imsi string) (*Personalization, error) {
	row := r.db.QueryRow("SELECT "+personalizationCols+
		" FROM personalization WHERE COALESCE(tenant_id,'') = ? AND imsi = ?", tenant, imsi)
	p, err := scanPersonalization(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: personalization imsi %q: %w", imsi, ErrNotFound)
	}
	return p, err
}

// List returns all personalization rows ordered by ICCID then IMSI.
func (r *PersonalizationRepo) List() ([]*Personalization, error) {
	rows, err := r.db.Query("SELECT " + personalizationCols + " FROM personalization ORDER BY COALESCE(iccid,''), COALESCE(imsi,'')")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return collectPersonalization(rows)
}

// ListPage returns a page of personalization rows (optionally filtered by ICCID
// prefix and/or tenant) plus the total count.
func (r *PersonalizationRepo) ListPage(iccidPrefix, tenant string, limit, offset int) ([]*Personalization, int, error) {
	var where []string
	var args []any
	if tenant != "" {
		where, args = append(where, "COALESCE(tenant_id,'') = ?"), append(args, tenant)
	}
	if iccidPrefix != "" {
		where, args = append(where, "iccid LIKE ?"), append(args, iccidPrefix+"%")
	}
	clause := buildWhere(where)
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM personalization"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query("SELECT "+personalizationCols+" FROM personalization"+clause+
		" ORDER BY COALESCE(iccid,''), COALESCE(imsi,'') LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	out, err := collectPersonalization(rows)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func collectPersonalization(rows *sql.Rows) ([]*Personalization, error) {
	var out []*Personalization
	for rows.Next() {
		p, err := scanPersonalization(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Delete removes a personalization row bound to an ICCID in a tenant.
func (r *PersonalizationRepo) Delete(tenant, iccid string) error {
	res, err := r.db.Exec(`DELETE FROM personalization WHERE iccid = ? AND COALESCE(tenant_id,'') = ?`, iccid, tenant)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReservePair binds the tenant's lowest unbound credentials-pool entry to iccid
// and returns its IMSI. It returns ErrNotFound when the tenant has no unbound
// credentials.
func (r *PersonalizationRepo) ReservePair(tenant, iccid string) (string, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	// An ICCID that goes back to the pool and is reserved again may still carry
	// the credentials of its previous owner's cycle; release that binding first
	// so the per-tenant unique index cannot be violated.
	if _, err := tx.Exec(`UPDATE personalization SET iccid = NULL, updated_at = ?
		WHERE COALESCE(tenant_id,'') = ? AND iccid = ? AND imsi IS NOT NULL`, unixNow(), tenant, iccid); err != nil {
		return "", err
	}
	var (
		id   int64
		imsi string
	)
	err = tx.QueryRow(`SELECT id, COALESCE(imsi,'') FROM personalization
		WHERE COALESCE(tenant_id,'') = ? AND iccid IS NULL AND imsi IS NOT NULL
		ORDER BY id LIMIT 1`, tenant).Scan(&id, &imsi)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE personalization SET iccid = ?, updated_at = ? WHERE id = ?`, iccid, unixNow(), id); err != nil {
		return "", err
	}
	return imsi, tx.Commit()
}

// BindPair binds a specific credentials-pool IMSI to an ICCID.
func (r *PersonalizationRepo) BindPair(tenant, imsi, iccid string) error {
	res, err := r.db.Exec(`UPDATE personalization SET iccid = ?, updated_at = ?
		WHERE COALESCE(tenant_id,'') = ? AND imsi = ? AND iccid IS NULL`, iccid, unixNow(), tenant, imsi)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UnbindPair returns a credentials-pool entry to the unbound state.
func (r *PersonalizationRepo) UnbindPair(tenant, iccid string) error {
	_, err := r.db.Exec(`UPDATE personalization SET iccid = NULL, updated_at = ?
		WHERE iccid = ? AND COALESCE(tenant_id,'') = ?`, unixNow(), iccid, tenant)
	return err
}

// CountUnbound reports the number of credentials-pool entries for a tenant.
func (r *PersonalizationRepo) CountUnbound(tenant string) (int, error) {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM personalization
		WHERE COALESCE(tenant_id,'') = ? AND iccid IS NULL AND imsi IS NOT NULL`, tenant).Scan(&n)
	return n, err
}
