package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
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
	return queryAll(r.db, "SELECT "+tenantCols+" FROM tenants ORDER BY id", nil, scanTenant)
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
	Ranges          int `json:"ranges"`
}

// Empty reports whether nothing references the tenant.
func (u TenantUsage) Empty() bool {
	return u.Profiles == 0 && u.Templates == 0 && u.PoolEntries == 0 &&
		u.Batches == 0 && u.Personalization == 0 && u.Ranges == 0
}

// tenantScopedTables are the resource tables carrying a tenant_id, each with the
// usage counter it feeds. A table that is missing here is silently left behind
// by a forced reassignment and undercounted by Usage, so the two halves cannot
// drift: they read the same list.
var tenantScopedTables = []struct {
	table string
	count func(*TenantUsage) *int
}{
	{"profiles", func(u *TenantUsage) *int { return &u.Profiles }},
	{"upp_templates", func(u *TenantUsage) *int { return &u.Templates }},
	{"iccid_pool", func(u *TenantUsage) *int { return &u.PoolEntries }},
	{"download_batches", func(u *TenantUsage) *int { return &u.Batches }},
	{"personalization", func(u *TenantUsage) *int { return &u.Personalization }},
	{"iccid_ranges", func(u *TenantUsage) *int { return &u.Ranges }},
}

// Usage counts every resource that references the tenant.
func (r *TenantRepo) Usage(id string) (TenantUsage, error) {
	var u TenantUsage
	for _, scope := range tenantScopedTables {
		if err := r.db.QueryRow("SELECT COUNT(*) FROM "+scope.table+" WHERE tenant_id = ?", id).
			Scan(scope.count(&u)); err != nil {
			return TenantUsage{}, err
		}
	}
	return u, nil
}

// ReassignConflictError reports that a forced tenant deletion cannot complete
// because the target scope already holds a resource with the same per-tenant
// unique key: profiles.external_ref, upp_templates.name (two tenants commonly
// both have a "default"), or personalization.imsi. It is a data conflict the
// operator has to resolve, not a server fault, so the management API answers a
// named 409 instead of a bare 500.
type ReassignConflictError struct {
	// Tables lists the conflicting resource tables, in tenantScopedTables order.
	Tables []string
}

func (e *ReassignConflictError) Error() string {
	return "store: reassign conflicts in " + strings.Join(e.Tables, ", ")
}

// DeleteWithReassign moves every resource of a tenant to reassignTo (an empty
// string means the platform-global scope, i.e. tenant_id = NULL) and then
// deletes the tenant, in one transaction. It returns ErrNotFound when the
// tenant does not exist, and *ReassignConflictError when a per-tenant unique
// index would be violated in the target scope.
func (r *TenantRepo) DeleteWithReassign(id, reassignTo string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	target := nullStr(reassignTo)
	var conflicts []string
	for _, scope := range tenantScopedTables {
		// The unique index is the authority (a pre-check would race), but its
		// violation must be reported by table rather than parsed out of the
		// driver's message. Each table is migrated inside a savepoint so a
		// conflict can be rolled back on its own and every conflicting table is
		// collected before the transaction is abandoned.
		if _, err := tx.Exec("SAVEPOINT reassign"); err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE "+scope.table+" SET tenant_id = ? WHERE tenant_id = ?", target, id); err != nil {
			if !IsUniqueViolation(err) {
				return err
			}
			if _, err := tx.Exec("ROLLBACK TO reassign"); err != nil {
				return err
			}
			if _, err := tx.Exec("RELEASE reassign"); err != nil {
				return err
			}
			conflicts = append(conflicts, scope.table)
			continue
		}
		if _, err := tx.Exec("RELEASE reassign"); err != nil {
			return err
		}
	}
	if len(conflicts) > 0 {
		return &ReassignConflictError{Tables: conflicts}
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
