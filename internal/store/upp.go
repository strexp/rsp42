package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// UPPTemplate is a row of the SAIP profile-package template registry.
type UPPTemplate struct {
	ID        int64
	Name      string
	SAIPMajor int
	SAIPMinor int
	SHA256    string
	Bytes     []byte
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UPPRepo persists UPP templates.
type UPPRepo struct{ db *sql.DB }

// Upsert inserts or replaces a template (keyed by name).
func (r *UPPRepo) Upsert(t *UPPTemplate) error {
	now := time.Now().UTC().Unix()
	created := now
	if !t.CreatedAt.IsZero() {
		created = t.CreatedAt.Unix()
	}
	_, err := r.db.Exec(`INSERT INTO upp_templates
		(name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
		 saip_major=excluded.saip_major, saip_minor=excluded.saip_minor,
		 sha256=excluded.sha256, bytes=excluded.bytes,
		 active=excluded.active, updated_at=excluded.updated_at`,
		t.Name, t.SAIPMajor, t.SAIPMinor, t.SHA256, t.Bytes, boolInt(t.Active), created, now)
	return err
}

// GetByName loads a template including its bytes.
func (r *UPPRepo) GetByName(name string) (*UPPTemplate, error) {
	row := r.db.QueryRow(`SELECT id, name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at
		FROM upp_templates WHERE name = ?`, name)
	t, err := scanUPP(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: upp template %q: %w", name, ErrNotFound)
	}
	return t, err
}

// List returns the template metadata (without bytes) ordered by SAIP version.
func (r *UPPRepo) List() ([]*UPPTemplate, error) {
	rows, err := r.db.Query(`SELECT id, name, saip_major, saip_minor, sha256, active, created_at, updated_at
		FROM upp_templates ORDER BY saip_major DESC, saip_minor DESC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*UPPTemplate
	for rows.Next() {
		t, err := scanUPP(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SelectBest returns the active template with the greatest SAIP version not
// exceeding (major, minor). With an unknown version (0) it returns the highest
// active template.
func (r *UPPRepo) SelectBest(major, minor int) (*UPPTemplate, error) {
	if major <= 0 {
		return r.Any()
	}
	row := r.db.QueryRow(`SELECT id, name, saip_major, saip_minor, sha256, active, created_at, updated_at
		FROM upp_templates
		WHERE active = 1 AND (saip_major < ? OR (saip_major = ? AND saip_minor <= ?))
		ORDER BY saip_major DESC, saip_minor DESC, name ASC LIMIT 1`, major, major, minor)
	t, err := scanUPP(row, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// Any returns the highest active template (metadata only).
func (r *UPPRepo) Any() (*UPPTemplate, error) {
	row := r.db.QueryRow(`SELECT id, name, saip_major, saip_minor, sha256, active, created_at, updated_at
		FROM upp_templates WHERE active = 1
		ORDER BY saip_major DESC, saip_minor DESC, name ASC LIMIT 1`)
	t, err := scanUPP(row, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// SetActive enables or disables a template.
func (r *UPPRepo) SetActive(name string, active bool) error {
	res, err := r.db.Exec(`UPDATE upp_templates SET active = ?, updated_at = ? WHERE name = ?`,
		boolInt(active), time.Now().UTC().Unix(), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a template.
func (r *UPPRepo) Delete(name string) error {
	res, err := r.db.Exec(`DELETE FROM upp_templates WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanUPP(sc rowScanner, withBytes bool) (*UPPTemplate, error) {
	var t UPPTemplate
	var active int
	var created, updated int64
	var err error
	if withBytes {
		err = sc.Scan(&t.ID, &t.Name, &t.SAIPMajor, &t.SAIPMinor, &t.SHA256, &t.Bytes, &active, &created, &updated)
	} else {
		err = sc.Scan(&t.ID, &t.Name, &t.SAIPMajor, &t.SAIPMinor, &t.SHA256, &active, &created, &updated)
	}
	if err != nil {
		return nil, err
	}
	t.Active = active != 0
	t.CreatedAt = toTime(created)
	t.UpdatedAt = toTime(updated)
	return &t, nil
}
