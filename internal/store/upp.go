package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"rsp42/internal/rsp"
)

// UPPTemplate is a row of the SAIP profile-package template registry.
type UPPTemplate struct {
	ID int64
	// TenantID is the owning carrier; NULL/"" marks a platform-global template.
	TenantID  string
	Name      string
	SAIPMajor int
	SAIPMinor int
	SHA256    string
	Bytes     []byte
	Active    bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UPPRepo persists UPP templates. Names are unique per tenant; a NULL tenant_id
// is the platform-global namespace.
type UPPRepo struct{ db *sql.DB }

const uppCols = `id, COALESCE(tenant_id,''), name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at`
const uppColsMeta = `id, COALESCE(tenant_id,''), name, saip_major, saip_minor, sha256, active, created_at, updated_at`

// Upsert inserts or replaces a template, scoped by (tenant, name).
func (r *UPPRepo) Upsert(t *UPPTemplate) error {
	now := time.Now().UTC().Unix()
	created := now
	if !t.CreatedAt.IsZero() {
		created = t.CreatedAt.Unix()
	}
	res, err := r.db.Exec(`UPDATE upp_templates SET
		 saip_major=?, saip_minor=?, sha256=?, bytes=?, active=?, updated_at=?
		 WHERE name=? AND COALESCE(tenant_id,'')=?`,
		t.SAIPMajor, t.SAIPMinor, t.SHA256, t.Bytes, boolInt(t.Active), now, t.Name, t.TenantID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = r.db.Exec(`INSERT INTO upp_templates
		(tenant_id, name, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		nullStr(t.TenantID), t.Name, t.SAIPMajor, t.SAIPMinor, t.SHA256, t.Bytes, boolInt(t.Active), created, now)
	return err
}

// GetScoped loads a template in exactly the given scope ("" = global).
func (r *UPPRepo) GetScoped(tenant, name string) (*UPPTemplate, error) {
	row := r.db.QueryRow(`SELECT `+uppCols+` FROM upp_templates WHERE name = ? AND COALESCE(tenant_id,'') = ?`, name, tenant)
	t, err := scanUPP(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: upp template %q (tenant %q): %w", name, tenant, ErrNotFound)
	}
	return t, err
}

// GetByName loads a platform-global template (tenant_id IS NULL).
func (r *UPPRepo) GetByName(name string) (*UPPTemplate, error) { return r.GetScoped("", name) }

// GetForTenant resolves a template for a tenant: the tenant's own template of
// that name wins, otherwise the platform-global one.
func (r *UPPRepo) GetForTenant(tenant, name string) (*UPPTemplate, error) {
	row := r.db.QueryRow(`SELECT `+uppCols+` FROM upp_templates
		WHERE name = ? AND (tenant_id = ? OR tenant_id IS NULL)
		ORDER BY CASE WHEN tenant_id IS NULL THEN 1 ELSE 0 END LIMIT 1`, name, nullStr(tenant))
	t, err := scanUPP(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: upp template %q (tenant %q): %w", name, tenant, ErrNotFound)
	}
	return t, err
}

// List returns all template metadata (without bytes).
func (r *UPPRepo) List() ([]*UPPTemplate, error) {
	return r.list(`SELECT ` + uppColsMeta + ` FROM upp_templates ORDER BY saip_major DESC, saip_minor DESC, name ASC`)
}

// ListForTenant returns the tenant's own templates plus the platform-global ones.
func (r *UPPRepo) ListForTenant(tenant string) ([]*UPPTemplate, error) {
	return r.list(`SELECT `+uppColsMeta+` FROM upp_templates WHERE tenant_id = ? OR tenant_id IS NULL
		ORDER BY saip_major DESC, saip_minor DESC, COALESCE(tenant_id,'') DESC, name ASC`, nullStr(tenant))
}

func (r *UPPRepo) list(query string, args ...any) ([]*UPPTemplate, error) {
	rows, err := r.db.Query(query, args...)
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

// SelectBestFor returns the active template with the greatest SAIP version that
// the eUICC's advertised version set supports, preferring the tenant's own
// template on a version tie. The caller passes the full set
// (profileVersion plus additionalEuiccProfilePackageVersions, N11); an empty
// set yields ErrNotFound rather than an arbitrary template, because
// "unknown version" must never silently select a template.
func (r *UPPRepo) SelectBestFor(tenant string, versions []rsp.Version) (*UPPTemplate, error) {
	best, ok := maxVersion(versions)
	if !ok {
		return nil, ErrNotFound
	}
	row := r.db.QueryRow(`SELECT `+uppColsMeta+` FROM upp_templates
		WHERE active = 1 AND (tenant_id = ? OR tenant_id IS NULL)
		  AND (saip_major < ? OR (saip_major = ? AND saip_minor <= ?))
		ORDER BY saip_major DESC, saip_minor DESC, CASE WHEN tenant_id IS NULL THEN 1 ELSE 0 END, name ASC LIMIT 1`,
		nullStr(tenant), best.Major, best.Major, best.Minor)
	t, err := scanUPP(row, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// maxVersion returns the highest version in a set.
func maxVersion(versions []rsp.Version) (rsp.Version, bool) {
	if len(versions) == 0 {
		return rsp.Version{}, false
	}
	best := versions[0]
	for _, v := range versions[1:] {
		if v.Compare(best) > 0 {
			best = v
		}
	}
	return best, true
}

// SelectBest is the platform-global variant of SelectBestFor.
func (r *UPPRepo) SelectBest(versions []rsp.Version) (*UPPTemplate, error) {
	return r.SelectBestFor("", versions)
}

// AnyForTenant returns the highest active template visible to a tenant
// (metadata only).
func (r *UPPRepo) AnyForTenant(tenant string) (*UPPTemplate, error) {
	row := r.db.QueryRow(`SELECT `+uppColsMeta+` FROM upp_templates
		WHERE active = 1 AND (tenant_id = ? OR tenant_id IS NULL)
		ORDER BY saip_major DESC, saip_minor DESC, CASE WHEN tenant_id IS NULL THEN 1 ELSE 0 END, name ASC LIMIT 1`,
		nullStr(tenant))
	t, err := scanUPP(row, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// Any returns the highest active platform-global template (metadata only).
func (r *UPPRepo) Any() (*UPPTemplate, error) { return r.AnyForTenant("") }

// SetActive enables or disables a template in a scope.
func (r *UPPRepo) SetActive(tenant, name string, active bool) error {
	res, err := r.db.Exec(`UPDATE upp_templates SET active = ?, updated_at = ? WHERE name = ? AND COALESCE(tenant_id,'') = ?`,
		boolInt(active), time.Now().UTC().Unix(), name, tenant)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a template from a scope.
func (r *UPPRepo) Delete(tenant, name string) error {
	res, err := r.db.Exec(`DELETE FROM upp_templates WHERE name = ? AND COALESCE(tenant_id,'') = ?`, name, tenant)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountForTenant returns how many templates a tenant owns (global ones excluded).
func (r *UPPRepo) CountForTenant(tenant string) (int, error) {
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM upp_templates WHERE tenant_id = ?`, nullStr(tenant)).Scan(&n)
	return n, err
}

type rowScanner interface{ Scan(dest ...any) error }

func scanUPP(sc rowScanner, withBytes bool) (*UPPTemplate, error) {
	var t UPPTemplate
	var active int
	var created, updated int64
	var err error
	if withBytes {
		err = sc.Scan(&t.ID, &t.TenantID, &t.Name, &t.SAIPMajor, &t.SAIPMinor, &t.SHA256, &t.Bytes, &active, &created, &updated)
	} else {
		err = sc.Scan(&t.ID, &t.TenantID, &t.Name, &t.SAIPMajor, &t.SAIPMinor, &t.SHA256, &active, &created, &updated)
	}
	if err != nil {
		return nil, err
	}
	t.Active = active != 0
	t.CreatedAt = toTime(created)
	t.UpdatedAt = toTime(updated)
	return &t, nil
}

// UPPTemplateVersion is one archived revision of a (tenant, name) template.
type UPPTemplateVersion struct {
	ID        int64
	TenantID  string
	Name      string
	VersionNo int
	SAIPMajor int
	SAIPMinor int
	SHA256    string
	Bytes     []byte
	Note      string
	CreatedAt time.Time
}

const uppVersionCols = `id, COALESCE(tenant_id,''), name, version_no, saip_major, saip_minor, sha256, bytes, note, created_at`

func scanUPPVersion(sc rowScanner) (*UPPTemplateVersion, error) {
	var v UPPTemplateVersion
	var note sql.NullString
	var created int64
	if err := sc.Scan(&v.ID, &v.TenantID, &v.Name, &v.VersionNo, &v.SAIPMajor, &v.SAIPMinor, &v.SHA256, &v.Bytes, &note, &created); err != nil {
		return nil, err
	}
	v.Note, v.CreatedAt = note.String, toTime(created)
	return &v, nil
}

// archiveCurrent snapshots the current template row into the version history.
// It is a no-op when the row does not exist or its bytes are unchanged.
func (r *UPPRepo) archiveCurrent(tenant, name, note string) error {
	cur, err := r.GetScoped(tenant, name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	var next int
	if err := r.db.QueryRow(`SELECT COALESCE(MAX(version_no),0)+1 FROM upp_template_versions
		WHERE COALESCE(tenant_id,'') = ? AND name = ?`, tenant, name).Scan(&next); err != nil {
		return err
	}
	if next > 1 {
		// Nothing new to archive when the bytes already match the last revision.
		var last string
		if err := r.db.QueryRow(`SELECT sha256 FROM upp_template_versions
			WHERE COALESCE(tenant_id,'') = ? AND name = ? ORDER BY version_no DESC LIMIT 1`,
			tenant, name).Scan(&last); err == nil && last == cur.SHA256 {
			return nil
		}
	}
	_, err = r.db.Exec(`INSERT INTO upp_template_versions
		(tenant_id, name, version_no, saip_major, saip_minor, sha256, bytes, note, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		nullStr(tenant), name, next, cur.SAIPMajor, cur.SAIPMinor, cur.SHA256, cur.Bytes, nullStr(note), unixNow())
	return err
}

// UpsertArchived is Upsert with version archiving: the template's previous
// revision is recorded before it is replaced.
func (r *UPPRepo) UpsertArchived(t *UPPTemplate, note string) error {
	if err := r.archiveCurrent(t.TenantID, t.Name, note); err != nil {
		return err
	}
	return r.Upsert(t)
}

// ListVersions returns the archived revisions of a template, newest first.
func (r *UPPRepo) ListVersions(tenant, name string) ([]*UPPTemplateVersion, error) {
	rows, err := r.db.Query(`SELECT `+uppVersionCols+` FROM upp_template_versions
		WHERE COALESCE(tenant_id,'') = ? AND name = ? ORDER BY version_no DESC`, tenant, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*UPPTemplateVersion
	for rows.Next() {
		v, err := scanUPPVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVersion loads one archived revision in a scope.
func (r *UPPRepo) GetVersion(tenant, name string, id int64) (*UPPTemplateVersion, error) {
	row := r.db.QueryRow(`SELECT `+uppVersionCols+` FROM upp_template_versions
		WHERE id = ? AND COALESCE(tenant_id,'') = ? AND name = ?`, id, tenant, name)
	v, err := scanUPPVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}
