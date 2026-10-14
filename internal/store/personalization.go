package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Personalization is a row of the per-ICCID personalization table. K and OPc are
// stored encrypted (the service layer encrypts/decrypts them).
type Personalization struct {
	ICCID          string
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
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PersonalizationRepo persists personalization rows (keyed by ICCID).
type PersonalizationRepo struct{ db *sql.DB }

const personalizationCols = `iccid, imsi, k, opc, pin1, puk1, adm1, adm2, spn, algorithm,
	rotation, xoring, number_of_keccak, created_at, updated_at`

// Upsert inserts or replaces a personalization row.
func (r *PersonalizationRepo) Upsert(p *Personalization) error {
	now := time.Now().UTC().Unix()
	created := now
	if !p.CreatedAt.IsZero() {
		created = p.CreatedAt.Unix()
	}
	_, err := r.db.Exec(`INSERT INTO personalization (`+personalizationCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(iccid) DO UPDATE SET
		 imsi=excluded.imsi, k=excluded.k, opc=excluded.opc,
		 pin1=excluded.pin1, puk1=excluded.puk1, adm1=excluded.adm1, adm2=excluded.adm2,
		 spn=excluded.spn, algorithm=excluded.algorithm,
		 rotation=excluded.rotation, xoring=excluded.xoring,
		 number_of_keccak=excluded.number_of_keccak, updated_at=excluded.updated_at`,
		p.ICCID, nullStr(p.IMSI), p.K, p.OPc, nullStr(p.PIN1), nullStr(p.PUK1),
		nullStr(p.ADM1), nullStr(p.ADM2), nullStr(p.SPN), nullStr(p.Algorithm),
		p.Rotation, p.Xoring, p.NumberOfKeccak, created, now)
	return err
}

// GetByICCID loads a personalization row (with encrypted secrets).
func (r *PersonalizationRepo) GetByICCID(iccid string) (*Personalization, error) {
	row := r.db.QueryRow("SELECT "+personalizationCols+" FROM personalization WHERE iccid = ?", iccid)
	p, err := scanPersonalization(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: personalization %q: %w", iccid, ErrNotFound)
	}
	return p, err
}

// List returns all personalization rows ordered by ICCID.
func (r *PersonalizationRepo) List() ([]*Personalization, error) {
	rows, err := r.db.Query("SELECT " + personalizationCols + " FROM personalization ORDER BY iccid")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
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

// ListPage returns a page of personalization rows (optionally filtered by ICCID
// prefix) plus the total count.
func (r *PersonalizationRepo) ListPage(iccidPrefix string, limit, offset int) ([]*Personalization, int, error) {
	clause := ""
	var args []any
	if iccidPrefix != "" {
		clause = " WHERE iccid LIKE ?"
		args = append(args, iccidPrefix+"%")
	}
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM personalization"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query("SELECT "+personalizationCols+" FROM personalization"+clause+
		" ORDER BY iccid LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Personalization
	for rows.Next() {
		p, err := scanPersonalization(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// Delete removes a personalization row.
func (r *PersonalizationRepo) Delete(iccid string) error {
	res, err := r.db.Exec(`DELETE FROM personalization WHERE iccid = ?`, iccid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanPersonalization(sc rowScanner) (*Personalization, error) {
	var p Personalization
	var imsi, pin1, puk1, adm1, adm2, spn, algo sql.NullString
	var keccak sql.NullInt64
	var created, updated int64
	if err := sc.Scan(&p.ICCID, &imsi, &p.K, &p.OPc, &pin1, &puk1, &adm1, &adm2, &spn, &algo,
		&p.Rotation, &p.Xoring, &keccak, &created, &updated); err != nil {
		return nil, err
	}
	p.IMSI, p.PIN1, p.PUK1, p.ADM1, p.ADM2, p.SPN, p.Algorithm =
		imsi.String, pin1.String, puk1.String, adm1.String, adm2.String, spn.String, algo.String
	if keccak.Valid {
		v := keccak.Int64
		p.NumberOfKeccak = &v
	}
	p.CreatedAt = toTime(created)
	p.UpdatedAt = toTime(updated)
	return &p, nil
}
