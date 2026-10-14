package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Tenant is an operator/carrier that owns resources in rsp42. The id is the
// upstream BSS's carrier primary key; rsp42 keeps no second mapping layer.
type Tenant struct {
	ID            string
	Name          string
	Status        string
	TemplateQuota *int
	ProfileQuota  *int
	DefaultUPP    string
	CallbackURL   string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Tenant statuses.
const (
	TenantActive   = "active"
	TenantDisabled = "disabled"
)

// TenantRepo persists the tenant registry.
type TenantRepo struct{ db *sql.DB }

const tenantCols = `id, name, status, template_quota, profile_quota, default_upp, callback_url, created_at, updated_at`

func scanTenant(sc rowScanner) (*Tenant, error) {
	var t Tenant
	var templateQuota, profileQuota sql.NullInt64
	var defaultUPP, callbackURL sql.NullString
	var created, updated int64
	if err := sc.Scan(&t.ID, &t.Name, &t.Status, &templateQuota, &profileQuota, &defaultUPP, &callbackURL, &created, &updated); err != nil {
		return nil, err
	}
	if templateQuota.Valid {
		v := int(templateQuota.Int64)
		t.TemplateQuota = &v
	}
	if profileQuota.Valid {
		v := int(profileQuota.Int64)
		t.ProfileQuota = &v
	}
	t.DefaultUPP, t.CallbackURL = defaultUPP.String, callbackURL.String
	t.CreatedAt, t.UpdatedAt = toTime(created), toTime(updated)
	return &t, nil
}

// Upsert inserts or replaces a tenant, preserving the original created_at.
func (r *TenantRepo) Upsert(t *Tenant) error {
	if t.ID == "" {
		return fmt.Errorf("store: tenant id is required")
	}
	if t.Status == "" {
		t.Status = TenantActive
	}
	now := time.Now().UTC()
	t.UpdatedAt = now
	created := now
	if !t.CreatedAt.IsZero() {
		created = t.CreatedAt
	} else {
		t.CreatedAt = created
	}
	_, err := r.db.Exec(`INSERT INTO tenants (`+tenantCols+`)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
		 name=excluded.name, status=excluded.status,
		 template_quota=excluded.template_quota, profile_quota=excluded.profile_quota,
		 default_upp=excluded.default_upp, callback_url=excluded.callback_url,
		 updated_at=excluded.updated_at`,
		t.ID, t.Name, t.Status, nullInt(t.TemplateQuota), nullInt(t.ProfileQuota),
		nullStr(t.DefaultUPP), nullStr(t.CallbackURL), created.Unix(), now.Unix())
	return err
}

// Get loads a tenant.
func (r *TenantRepo) Get(id string) (*Tenant, error) {
	row := r.db.QueryRow("SELECT "+tenantCols+" FROM tenants WHERE id = ?", id)
	t, err := scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: tenant %q: %w", id, ErrNotFound)
	}
	return t, err
}

// List returns all tenants ordered by id.
func (r *TenantRepo) List() ([]*Tenant, error) {
	rows, err := r.db.Query("SELECT " + tenantCols + " FROM tenants ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Delete removes a tenant. Resources keep their tenant_id (dangling by design:
// the registry is a control-plane view, not a referential parent).
func (r *TenantRepo) Delete(id string) error {
	res, err := r.db.Exec("DELETE FROM tenants WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TenantUsage counts the resources that reference a tenant (N3). It is the
// guard that turns a tenant deletion into a two-phase, recoverable operation.
type TenantUsage struct {
	Profiles        int `json:"profiles"`
	Templates       int `json:"templates"`
	PoolEntries     int `json:"poolEntries"`
	Batches         int `json:"batches"`
	Personalization int `json:"personalization"`
}

// Empty reports whether nothing references the tenant.
func (u TenantUsage) Empty() bool {
	return u.Profiles == 0 && u.Templates == 0 && u.PoolEntries == 0 &&
		u.Batches == 0 && u.Personalization == 0
}

// tenantScopedTables are the resource tables carrying a tenant_id.
var tenantScopedTables = []string{
	"profiles", "upp_templates", "iccid_pool", "download_batches", "personalization",
}

// Usage counts every resource that references the tenant.
func (r *TenantRepo) Usage(id string) (TenantUsage, error) {
	var u TenantUsage
	dst := []*int{&u.Profiles, &u.Templates, &u.PoolEntries, &u.Batches, &u.Personalization}
	for i, table := range tenantScopedTables {
		if err := r.db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE tenant_id = ?", id).Scan(dst[i]); err != nil {
			return TenantUsage{}, err
		}
	}
	return u, nil
}

// DeleteWithReassign moves every resource of a tenant to reassignTo (an empty
// string means the platform-global scope, i.e. tenant_id = NULL) and then
// deletes the tenant, in one transaction. It returns ErrNotFound when the
// tenant does not exist.
func (r *TenantRepo) DeleteWithReassign(id, reassignTo string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	target := nullStr(reassignTo)
	for _, table := range tenantScopedTables {
		if _, err := tx.Exec("UPDATE "+table+" SET tenant_id = ? WHERE tenant_id = ?", target, id); err != nil {
			return err
		}
	}
	res, err := tx.Exec("DELETE FROM tenants WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func nullInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

// DefaultUPPForTenant returns the tenant's configured default template name, or
// "" when unset or unknown.
func (r *TenantRepo) DefaultUPPForTenant(tenant string) (string, error) {
	if tenant == "" {
		return "", nil
	}
	t, err := r.Get(tenant)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return t.DefaultUPP, nil
}

// CallbackURLForTenant returns the tenant's progress-callback override, or ""
// when unset or unknown.
func (r *TenantRepo) CallbackURLForTenant(tenant string) (string, error) {
	if tenant == "" {
		return "", nil
	}
	t, err := r.Get(tenant)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return t.CallbackURL, nil
}
