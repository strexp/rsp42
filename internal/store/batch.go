package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// DownloadBatch groups a list of profiles/orders managed together (a "download
// list"). The individual profiles carry `batch_id`.
type DownloadBatch struct {
	ID int64
	// TenantID is the owning carrier; empty is the platform default.
	TenantID    string
	Name        string
	ProfileType string
	State       string // Open | Completed | Cancelled
	Total       int
	Note        string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// BatchRepo persists download batches.
type BatchRepo struct{ db *sql.DB }

const batchCols = `id, COALESCE(tenant_id,''), name, profile_type, state, total, note, created_at, updated_at`

// Insert stores a batch and returns its id.
func (r *BatchRepo) Insert(b *DownloadBatch) (int64, error) {
	now := time.Now().UTC().Unix()
	res, err := r.db.Exec(`INSERT INTO download_batches (tenant_id, name, profile_type, state, total, note, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		nullStr(b.TenantID), nullStr(b.Name), nullStr(b.ProfileType), b.State, b.Total, nullStr(b.Note), now, now)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	b.ID = id
	return id, nil
}

// Get loads a batch by id.
func (r *BatchRepo) Get(id int64) (*DownloadBatch, error) {
	row := r.db.QueryRow("SELECT "+batchCols+" FROM download_batches WHERE id = ?", id)
	b, err := scanBatch(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: batch %d: %w", id, ErrNotFound)
	}
	return b, err
}

// List returns a page of batches (newest first) and the total count. tenant
// limits the listing to one owner; "" selects the platform-default owner.
func (r *BatchRepo) List(tenant string, limit, offset int) ([]*DownloadBatch, int, error) {
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM download_batches WHERE COALESCE(tenant_id,'') = ?", tenant).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query("SELECT "+batchCols+" FROM download_batches WHERE COALESCE(tenant_id,'') = ? ORDER BY id DESC LIMIT ? OFFSET ?", tenant, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []*DownloadBatch
	for rows.Next() {
		b, err := scanBatch(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, b)
	}
	return out, total, rows.Err()
}

// UpdateState sets the batch state.
func (r *BatchRepo) UpdateState(id int64, state string) error {
	_, err := r.db.Exec("UPDATE download_batches SET state = ?, updated_at = ? WHERE id = ?",
		state, time.Now().UTC().Unix(), id)
	return err
}

// Delete removes a batch (profiles keep their rows; batch_id becomes dangling).
func (r *BatchRepo) Delete(id int64) error {
	res, err := r.db.Exec("DELETE FROM download_batches WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanBatch(sc rowScanner) (*DownloadBatch, error) {
	var b DownloadBatch
	var name, ptype, note sql.NullString
	var created, updated int64
	if err := sc.Scan(&b.ID, &b.TenantID, &name, &ptype, &b.State, &b.Total, &note, &created, &updated); err != nil {
		return nil, err
	}
	b.Name, b.ProfileType, b.Note = name.String, ptype.String, note.String
	b.CreatedAt, b.UpdatedAt = toTime(created), toTime(updated)
	return &b, nil
}
