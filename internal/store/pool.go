package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"rsp42/internal/iccid"
)

// ICCIDPoolEntry is a row of the ICCID pool.
type ICCIDPoolEntry struct {
	ICCID string
	// TenantID empty means the platform-default pool.
	TenantID      string
	State         string // available | allocated | blocked
	RangeID       *int64
	EID           string
	BatchID       *int64
	Reference     string
	ProfileID     *int64
	Note          string
	ReservedUntil *time.Time
	AllocatedAt   *time.Time
	CreatedAt     time.Time
}

// ICCIDRange is an imported ICCID range.
type ICCIDRange struct {
	ID        int64
	TenantID  string
	Start     string
	End       string
	Note      string
	CreatedAt time.Time
}

// maxRangeSize bounds how many ICCIDs a single range import may materialize.
const maxRangeSize = 1000000

// PoolRepo manages the ICCID inventory (ranges + pool).
type PoolRepo struct{ db *sql.DB }

// ImportRange validates and materializes [start,end] into the pool as available
// ICCIDs, recording the range. Invalid (non-Luhn) ICCIDs are skipped. ICCIDs
// already present keep their existing owner.
func (r *PoolRepo) ImportRange(tenant, start, end, note string) (rangeID int64, inserted, skipped int, err error) {
	start, end = iccid.Normalize(start), iccid.Normalize(end)
	if len(start) != len(end) || len(start) < 19 || len(start) > 20 {
		return 0, 0, 0, fmt.Errorf("store: range bounds must be the same length (19-20 digits)")
	}
	lo, ok1 := new(big.Int).SetString(start, 10)
	hi, ok2 := new(big.Int).SetString(end, 10)
	if !ok1 || !ok2 || lo.Cmp(hi) > 0 {
		return 0, 0, 0, fmt.Errorf("store: invalid range %s..%s", start, end)
	}
	count := new(big.Int).Sub(hi, lo)
	count.Add(count, big.NewInt(1))
	if count.Cmp(big.NewInt(maxRangeSize)) > 0 {
		return 0, 0, 0, fmt.Errorf("store: range %s..%s exceeds %d ICCIDs", start, end, maxRangeSize)
	}

	now := time.Now().UTC().Unix()
	tx, err := r.db.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`INSERT INTO iccid_ranges (start, end, note, tenant_id, created_at) VALUES (?,?,?,?,?)`,
		start, end, nullStr(note), nullStr(tenant), now)
	if err != nil {
		return 0, 0, 0, err
	}
	rangeID, _ = res.LastInsertId()

	stmt, err := tx.Prepare(`INSERT INTO iccid_pool (iccid, state, range_id, tenant_id, created_at)
		VALUES (?, 'available', ?, ?, ?) ON CONFLICT(iccid) DO NOTHING`)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = stmt.Close() }()

	cur := new(big.Int).Set(lo)
	width := len(start)
	for i := 0; i < int(count.Int64()); i++ {
		num := fmt.Sprintf("%0*s", width, cur.String())
		if !iccid.LuhnValid(num) {
			skipped++
			cur.Add(cur, big.NewInt(1))
			continue
		}
		rr, err := stmt.Exec(num, rangeID, nullStr(tenant), now)
		if err != nil {
			return 0, 0, 0, err
		}
		if n, _ := rr.RowsAffected(); n > 0 {
			inserted++
		} else {
			skipped++ // already present
		}
		cur.Add(cur, big.NewInt(1))
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, 0, err
	}
	return rangeID, inserted, skipped, nil
}

// Reserve takes the lowest available ICCID in the tenant's scope and marks it
// allocated. reference is the caller's order/claim id; ttl bounds how long the
// reservation may stay unclaimed before the GC returns it to the pool. It
// returns ErrNotFound when the scope has no available ICCID.
func (r *PoolRepo) Reserve(tenant, eid, reference string, ttl time.Duration) (string, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	var iccid string
	err = tx.QueryRow(`SELECT iccid FROM iccid_pool WHERE state = 'available' AND COALESCE(tenant_id,'') = ?
		ORDER BY iccid LIMIT 1`, tenant).Scan(&iccid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	var reservedUntil any
	if ttl > 0 {
		reservedUntil = time.Now().UTC().Add(ttl).Unix()
	}
	if _, err := tx.Exec(`UPDATE iccid_pool SET state = 'allocated', eid = ?, reference = ?,
		allocated_at = ?, reserved_until = ? WHERE iccid = ?`,
		nullStr(eid), nullStr(reference), time.Now().UTC().Unix(), reservedUntil, iccid); err != nil {
		return "", err
	}
	return iccid, tx.Commit()
}

// State returns a pool entry's state, or ErrNotFound when the ICCID is not in
// the pool at all.
func (r *PoolRepo) State(iccid string) (string, error) {
	var state string
	err := r.db.QueryRow(`SELECT state FROM iccid_pool WHERE iccid = ?`, iccid).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return state, err
}

// Claim attaches an ICCID to a profile: the reservation deadline is cleared (so
// it is no longer a GC candidate), the entry is marked allocated if it was
// still available, and the owning profile is recorded. A blocked entry is left
// untouched.
func (r *PoolRepo) Claim(iccid string, profileID int64) error {
	_, err := r.db.Exec(`UPDATE iccid_pool SET
		reserved_until = NULL,
		profile_id = ?,
		state = CASE WHEN state = 'available' THEN 'allocated' ELSE state END,
		allocated_at = COALESCE(allocated_at, ?)
		WHERE iccid = ?`, profileID, unixNow(), iccid)
	return err
}

// ReleaseExpired returns lapsed reservations to the pool. It returns how many
// entries were reclaimed.
//
// An entry that already owns a profile (profile_id is set) is never reclaimed:
// doing so would hand the same ICCID out again while a profile still references
// it. A claim that failed leaves the reservation without a profile_id, and is
// reclaimed here.
func (r *PoolRepo) ReleaseExpired(now time.Time) (int64, error) {
	res, err := r.db.Exec(`UPDATE iccid_pool SET state = 'available', eid = NULL, reference = NULL,
		profile_id = NULL, allocated_at = NULL, reserved_until = NULL
		WHERE state = 'allocated' AND reserved_until IS NOT NULL AND reserved_until < ?
		  AND profile_id IS NULL`, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetState changes an entry's state (e.g. release an allocated ICCID back to
// available, or block it). Releasing clears the reservation metadata.
func (r *PoolRepo) SetState(iccid, state, note string) error {
	res, err := r.db.Exec(`UPDATE iccid_pool SET state = ?,
		eid = CASE WHEN ? = 'available' THEN NULL ELSE eid END,
		reference = CASE WHEN ? = 'available' THEN NULL ELSE reference END,
		profile_id = CASE WHEN ? = 'available' THEN NULL ELSE profile_id END,
		allocated_at = CASE WHEN ? = 'available' THEN NULL ELSE allocated_at END,
		reserved_until = CASE WHEN ? = 'available' THEN NULL ELSE reserved_until END,
		note = COALESCE(NULLIF(?,''), note) WHERE iccid = ?`,
		state, state, state, state, state, state, note, iccid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Stats returns counts by state plus the number of ranges. A nil tenant
// aggregates every owner; non-nil limits to that owner ("" = platform default).
func (r *PoolRepo) Stats(tenant *string) (counts map[string]int, ranges int, err error) {
	counts = map[string]int{}
	where, args := "", []any{}
	if tenant != nil {
		where, args = " WHERE COALESCE(tenant_id,'') = ?", []any{*tenant}
	}
	rows, err := r.db.Query(`SELECT state, COUNT(*) FROM iccid_pool`+where+` GROUP BY state`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			return nil, 0, err
		}
		counts[state] = n
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM iccid_ranges`+where, args...).Scan(&ranges); err != nil {
		return nil, 0, err
	}
	expiredWhere := " WHERE state = 'allocated' AND reserved_until IS NOT NULL AND reserved_until < ?"
	expiredArgs := []any{time.Now().UTC().Unix()}
	if tenant != nil {
		expiredWhere += " AND COALESCE(tenant_id,'') = ?"
		expiredArgs = append(expiredArgs, *tenant)
	}
	var expired int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM iccid_pool`+expiredWhere, expiredArgs...).Scan(&expired); err != nil {
		return nil, 0, err
	}
	counts["reservation_expired"] = expired
	return counts, ranges, rows.Err()
}

// ListPage returns a page of pool entries plus the total count. A nil tenant
// spans every owner.
func (r *PoolRepo) ListPage(state, prefix string, tenant *string, limit, offset int) ([]*ICCIDPoolEntry, int, error) {
	var where []string
	var args []any
	if tenant != nil {
		where, args = append(where, "COALESCE(tenant_id,'') = ?"), append(args, *tenant)
	}
	if state != "" {
		where, args = append(where, "state = ?"), append(args, state)
	}
	if prefix != "" {
		where, args = append(where, "iccid LIKE ?"), append(args, prefix+"%")
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM iccid_pool"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	out, err := queryAll(r.db, "SELECT "+poolCols+" FROM iccid_pool"+
		clause+" ORDER BY iccid LIMIT ? OFFSET ?", append(args, limit, offset), scanPool)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ListRanges returns the imported ranges (newest first). A nil tenant spans
// every owner.
func (r *PoolRepo) ListRanges(tenant *string) ([]*ICCIDRange, error) {
	query := `SELECT id, COALESCE(tenant_id,''), start, end, note, created_at FROM iccid_ranges`
	var args []any
	if tenant != nil {
		query += ` WHERE COALESCE(tenant_id,'') = ?`
		args = append(args, *tenant)
	}
	return queryAll(r.db, query+` ORDER BY id DESC`, args, scanICCIDRange)
}

// scanICCIDRange maps one iccid_ranges row.
func scanICCIDRange(sc rowScanner) (*ICCIDRange, error) {
	var rg ICCIDRange
	var note sql.NullString
	var created int64
	if err := sc.Scan(&rg.ID, &rg.TenantID, &rg.Start, &rg.End, &note, &created); err != nil {
		return nil, err
	}
	rg.Note = note.String
	rg.CreatedAt = toTime(created)
	return &rg, nil
}

// DeleteRange removes an imported range and its still-available pool entries in
// one transaction, so a failure cannot leave the range row without its entries
// (or the reverse).
func (r *PoolRepo) DeleteRange(id int64) (removed int, err error) {
	err = withTx(r.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM iccid_pool WHERE range_id = ? AND state = 'available'`, id)
		if err != nil {
			return err
		}
		removed64, _ := res.RowsAffected()
		removed = int(removed64)

		res, err = tx.Exec(`DELETE FROM iccid_ranges WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return removed, err
	}
	return removed, nil
}

const poolCols = `iccid, COALESCE(tenant_id,''), state, range_id, eid, batch_id, reference, profile_id, note,
	reserved_until, allocated_at, created_at`

func scanPool(sc rowScanner) (*ICCIDPoolEntry, error) {
	var e ICCIDPoolEntry
	var rangeID, batchID, profileID, reservedUntil, allocatedAt sql.NullInt64
	var eid, reference, note sql.NullString
	var created int64
	if err := sc.Scan(&e.ICCID, &e.TenantID, &e.State, &rangeID, &eid, &batchID, &reference, &profileID, &note,
		&reservedUntil, &allocatedAt, &created); err != nil {
		return nil, err
	}
	if rangeID.Valid {
		v := rangeID.Int64
		e.RangeID = &v
	}
	if batchID.Valid {
		v := batchID.Int64
		e.BatchID = &v
	}
	if profileID.Valid {
		v := profileID.Int64
		e.ProfileID = &v
	}
	if reservedUntil.Valid {
		t := toTime(reservedUntil.Int64)
		e.ReservedUntil = &t
	}
	if allocatedAt.Valid {
		t := toTime(allocatedAt.Int64)
		e.AllocatedAt = &t
	}
	e.EID, e.Reference, e.Note, e.CreatedAt = eid.String, reference.String, note.String, toTime(created)
	return &e, nil
}
