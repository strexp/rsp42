package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// Sealer is the encryption seam the rekey needs. It is declared by the consumer
// so the persistence layer does not depend on the KMS package;
// *kms.FileProvider satisfies it (asserted in rekey_test.go).
type Sealer interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// encryptedColumnSet names the KEK-encrypted columns of one table and the key
// that identifies a row.
//
// It is the single list of encrypted columns: the service layer encrypts these
// fields (service.SessionService.Put, service.PersonalizationService.Put), and
// Rekey is the only thing that has to know all of them. A new encrypted column
// must be added here or the KEK rotation silently leaves it behind.
var encryptedColumnSet = []struct {
	table  string
	keyCol string
	cols   []string
}{
	{
		table:  "sessions",
		keyCol: "transaction_id",
		cols:   []string{"server_challenge", "smdp_ot_sk", "shared_secret", "cc_hash"},
	},
	{
		table:  "personalization",
		keyCol: "id",
		cols:   []string{"k", "opc"},
	},
}

// RekeyResult reports what a Rekey call did.
type RekeyResult struct {
	// Rotated counts values re-encrypted from the old KEK to the new one.
	Rotated int
	// Current counts values already sealed with the new KEK. A run that finds
	// only Current values did nothing, which is what makes a resumed run safe.
	Current int
	// Empty counts NULL or zero-length values, which carry no key material.
	Empty int
}

// Rekey re-encrypts every KEK-protected value from the old sealer to the new
// one and returns what it did.
//
// Each table is rewritten in one transaction: either every value of that table
// moves to the new KEK or none does, so an interrupted run cannot leave a mix
// that no single key can open. A resumed run is a no-op for values already
// sealed with `to`, so re-running after an interruption completes the job.
//
// A value that neither the new nor the old sealer can open is an error and
// rolls the table back: it means the row was sealed with a third key (or is
// corrupt), and guessing would lose the material.
func Rekey(db *sql.DB, from, to Sealer) (RekeyResult, error) {
	var total RekeyResult
	for _, set := range encryptedColumnSet {
		got, err := rekeyTable(db, set.table, set.keyCol, set.cols, from, to)
		if err != nil {
			return total, err
		}
		total.Rotated += got.Rotated
		total.Current += got.Current
		total.Empty += got.Empty
	}
	return total, nil
}

// Rekey runs Rekey against this store's database.
func (s *Store) Rekey(from, to Sealer) (RekeyResult, error) {
	return Rekey(s.DB, from, to)
}

// rekeyTable rewrites the encrypted columns of one table in a single
// transaction. The rows are read into memory before any UPDATE: the store runs
// on a single connection (SetMaxOpenConns(1)), so issuing a write while a read
// cursor is open would wait on itself.
func rekeyTable(db *sql.DB, table, keyCol string, cols []string, from, to Sealer) (RekeyResult, error) {
	var out RekeyResult
	err := withTx(db, func(tx *sql.Tx) error {
		selectCols := strings.Join(append([]string{keyCol}, cols...), ", ")
		rows, err := tx.Query("SELECT " + selectCols + " FROM " + table)
		if err != nil {
			return err
		}

		type rowValues struct {
			key  any
			vals [][]byte
		}
		var all []rowValues
		for rows.Next() {
			key := new(any)
			raw := make([]sql.RawBytes, len(cols))
			dest := make([]any, 0, 1+len(cols))
			dest = append(dest, key)
			for i := range raw {
				dest = append(dest, &raw[i])
			}
			if err := rows.Scan(dest...); err != nil {
				_ = rows.Close()
				return err
			}
			vals := make([][]byte, len(cols))
			for i := range raw {
				// RawBytes is only valid until the next Scan: copy now.
				vals[i] = append([]byte(nil), raw[i]...)
			}
			all = append(all, rowValues{key: *key, vals: vals})
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}

		setClause := make([]string, len(cols))
		for i, c := range cols {
			setClause[i] = c + "=?"
		}
		update := "UPDATE " + table + " SET " + strings.Join(setClause, ", ") + " WHERE " + keyCol + " = ?"

		for _, rv := range all {
			args := make([]any, 0, len(cols)+1)
			rotated := 0
			for i, cur := range rv.vals {
				switch {
				case len(cur) == 0:
					out.Empty++
				case opens(to, cur):
					// Already sealed with the new KEK: a resumed run.
					out.Current++
				default:
					pt, err := from.Decrypt(cur)
					if err != nil {
						return fmt.Errorf("store: rekey %s.%s: row %v is not sealed with the current KEK: %w",
							table, cols[i], rv.key, err)
					}
					ct, err := to.Encrypt(pt)
					if err != nil {
						return err
					}
					rv.vals[i] = ct
					out.Rotated++
					rotated++
				}
				args = append(args, rv.vals[i])
			}
			if rotated == 0 {
				continue
			}
			args = append(args, rv.key)
			if _, err := tx.Exec(update, args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return RekeyResult{}, err
	}
	return out, nil
}

// opens reports whether the sealer can open ciphertext.
func opens(s Sealer, ciphertext []byte) bool {
	_, err := s.Decrypt(ciphertext)
	return err == nil
}
