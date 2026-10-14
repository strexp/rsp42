package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"rsp42/internal/rsp"
)

// ICCIDPoolEntry is a row of the ICCID pool.
type ICCIDPoolEntry struct {
	ICCID       string
	State       string // available | allocated | blocked
	RangeID     *int64
	EID         string
	BatchID     *int64
	Note        string
	AllocatedAt *time.Time
	CreatedAt   time.Time
}

// ICCIDRange is an imported ICCID range.
type ICCIDRange struct {
	ID        int64
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
// ICCIDs, recording the range. Invalid (non-Luhn) ICCIDs are skipped.
func (r *PoolRepo) ImportRange(start, end, note string) (rangeID int64, inserted, skipped int, err error) {
	start, end = strings.TrimRight(start, "fF"), strings.TrimRight(end, "fF")
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
	res, err := tx.Exec(`INSERT INTO iccid_ranges (start, end, note, created_at) VALUES (?,?,?,?)`,
		start, end, nullStr(note), now)
	if err != nil {
		return 0, 0, 0, err
	}
	rangeID, _ = res.LastInsertId()

	stmt, err := tx.Prepare(`INSERT INTO iccid_pool (iccid, state, range_id, created_at)
		VALUES (?, 'available', ?, ?) ON CONFLICT(iccid) DO NOTHING`)
	if err != nil {
		return 0, 0, 0, err
	}
	defer func() { _ = stmt.Close() }()

	cur := new(big.Int).Set(lo)
	width := len(start)
	for i := 0; i < int(count.Int64()); i++ {
		iccid := fmt.Sprintf("%0*s", width, cur.String())
		if !rsp.LuhnValid(iccid) {
			skipped++
			cur.Add(cur, big.NewInt(1))
			continue
		}
		rr, err := stmt.Exec(iccid, rangeID, now)
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

// Reserve atomically takes the lowest available ICCID and marks it allocated.
// It returns ErrNotFound when the pool has no available ICCID.
func (r *PoolRepo) Reserve(eid string) (string, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	var iccid string
	err = tx.QueryRow(`SELECT iccid FROM iccid_pool WHERE state = 'available' ORDER BY iccid LIMIT 1`).Scan(&iccid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE iccid_pool SET state = 'allocated', eid = ?, allocated_at = ? WHERE iccid = ?`,
		nullStr(eid), time.Now().UTC().Unix(), iccid); err != nil {
		return "", err
	}
	return iccid, tx.Commit()
}

// SetState changes an entry's state (e.g. release an allocated ICCID back to
// available, or block it).
func (r *PoolRepo) SetState(iccid, state, note string) error {
	res, err := r.db.Exec(`UPDATE iccid_pool SET state = ?, eid = CASE WHEN ? = 'available' THEN NULL ELSE eid END,
		allocated_at = CASE WHEN ? = 'available' THEN NULL ELSE allocated_at END,
		note = COALESCE(NULLIF(?,''), note) WHERE iccid = ?`,
		state, state, state, note, iccid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Stats returns counts by state plus the number of ranges.
func (r *PoolRepo) Stats() (counts map[string]int, ranges int, err error) {
	counts = map[string]int{}
	rows, err := r.db.Query(`SELECT state, COUNT(*) FROM iccid_pool GROUP BY state`)
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
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM iccid_ranges`).Scan(&ranges); err != nil {
		return nil, 0, err
	}
	return counts, ranges, rows.Err()
}

// ListPage returns a page of pool entries plus the total count.
func (r *PoolRepo) ListPage(state, prefix string, limit, offset int) ([]*ICCIDPoolEntry, int, error) {
	var where []string
	var args []any
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
	rows, err := r.db.Query("SELECT iccid, state, range_id, eid, batch_id, note, allocated_at, created_at FROM iccid_pool"+
		clause+" ORDER BY iccid LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []*ICCIDPoolEntry
	for rows.Next() {
		e, err := scanPool(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// ListRanges returns the imported ranges (newest first).
func (r *PoolRepo) ListRanges() ([]*ICCIDRange, error) {
	rows, err := r.db.Query(`SELECT id, start, end, note, created_at FROM iccid_ranges ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*ICCIDRange
	for rows.Next() {
		var rg ICCIDRange
		var note sql.NullString
		var created int64
		if err := rows.Scan(&rg.ID, &rg.Start, &rg.End, &note, &created); err != nil {
			return nil, err
		}
		rg.Note = note.String
		rg.CreatedAt = toTime(created)
		out = append(out, &rg)
	}
	return out, rows.Err()
}

// DeleteRange removes an imported range and its still-available pool entries.
func (r *PoolRepo) DeleteRange(id int64) (removed int, err error) {
	res, err := r.db.Exec(`DELETE FROM iccid_pool WHERE range_id = ? AND state = 'available'`, id)
	if err != nil {
		return 0, err
	}
	removed64, _ := res.RowsAffected()
	res, err = r.db.Exec(`DELETE FROM iccid_ranges WHERE id = ?`, id)
	if err != nil {
		return int(removed64), err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return int(removed64), ErrNotFound
	}
	return int(removed64), nil
}

func scanPool(sc rowScanner) (*ICCIDPoolEntry, error) {
	var e ICCIDPoolEntry
	var rangeID, batchID, allocatedAt sql.NullInt64
	var eid, note sql.NullString
	var created int64
	if err := sc.Scan(&e.ICCID, &e.State, &rangeID, &eid, &batchID, &note, &allocatedAt, &created); err != nil {
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
	if allocatedAt.Valid {
		t := toTime(allocatedAt.Int64)
		e.AllocatedAt = &t
	}
	e.EID, e.Note, e.CreatedAt = eid.String, note.String, toTime(created)
	return &e, nil
}
