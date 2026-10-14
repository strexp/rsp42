package service

import (
	"errors"
	"fmt"

	"rsp42/internal/kms"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
)

// PersonalizationStore is the persistence subset used by PersonalizationService.
type PersonalizationStore interface {
	GetByICCID(iccid string) (*store.Personalization, error)
	Upsert(p *store.Personalization) error
	Delete(iccid string) error
	List() ([]*store.Personalization, error)
	ListPage(iccidPrefix string, limit, offset int) ([]*store.Personalization, int, error)
}

// PersonalizationResolver resolves a profile's personalization values.
type PersonalizationResolver interface {
	Resolve(iccid string) (*personalization.Data, error)
}

// PersonalizationService persists per-ICCID personalization, encrypting K/OPc at
// rest with the KMS key-encryption key. Resolving by ICCID replaces the previous
// global Source cursor, removing its shared mutable state (and data race).
type PersonalizationService struct {
	Repo PersonalizationStore
	KMS  kms.Provider
}

// NewPersonalizationService builds a PersonalizationService.
func NewPersonalizationService(repo PersonalizationStore, provider kms.Provider) *PersonalizationService {
	return &PersonalizationService{Repo: repo, KMS: provider}
}

// Resolve returns the personalization for an ICCID, or (nil, nil) when none is
// registered.
func (s *PersonalizationService) Resolve(iccid string) (*personalization.Data, error) {
	row, err := s.Repo.GetByICCID(iccid)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.decrypt(row)
}

// Put encrypts K/OPc and stores the record.
func (s *PersonalizationService) Put(d *personalization.Data) error {
	if d.ICCID == "" {
		return fmt.Errorf("personalization: iccid is required")
	}
	row := &store.Personalization{
		ICCID: d.ICCID, IMSI: d.IMSI, PIN1: d.PIN1, PUK1: d.PUK1, ADM1: d.ADM1, ADM2: d.ADM2,
		SPN: d.SPN, Algorithm: d.Algorithm,
		Rotation: d.RotationConstants, Xoring: d.XoringConstants, NumberOfKeccak: d.NumberOfKeccak,
	}
	if len(d.K) > 0 {
		ct, err := s.KMS.Encrypt(d.K)
		if err != nil {
			return err
		}
		row.K = ct
	}
	if len(d.OPc) > 0 {
		ct, err := s.KMS.Encrypt(d.OPc)
		if err != nil {
			return err
		}
		row.OPc = ct
	}
	return s.Repo.Upsert(row)
}

// Delete removes a record.
func (s *PersonalizationService) Delete(iccid string) error { return s.Repo.Delete(iccid) }

// List returns all records (decrypted), ordered by ICCID.
func (s *PersonalizationService) List() ([]*personalization.Data, error) {
	rows, err := s.Repo.List()
	if err != nil {
		return nil, err
	}
	out := make([]*personalization.Data, 0, len(rows))
	for _, row := range rows {
		d, err := s.decrypt(row)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// ListPage returns a page of decrypted records (optionally filtered by ICCID
// prefix) plus the total count.
func (s *PersonalizationService) ListPage(iccidPrefix string, limit, offset int) ([]*personalization.Data, int, error) {
	rows, total, err := s.Repo.ListPage(iccidPrefix, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*personalization.Data, 0, len(rows))
	for _, row := range rows {
		d, err := s.decrypt(row)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, nil
}

// Import loads records from a personalization Source into the database. It is the
// only path that reads the CSV/file source; runtime downloads resolve from the
// database.
func (s *PersonalizationService) Import(kind, path string, mapping map[string]string, static []*personalization.Data) (int, error) {
	src, err := personalization.NewSource(kind, path, mapping, static)
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		d, err := src.Next()
		if err != nil {
			return n, err
		}
		if d == nil {
			break
		}
		if d.ICCID == "" {
			return n, fmt.Errorf("personalization import: row %d has no ICCID", n+1)
		}
		if err := s.Put(d); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (s *PersonalizationService) decrypt(row *store.Personalization) (*personalization.Data, error) {
	d := &personalization.Data{
		ICCID: row.ICCID, IMSI: row.IMSI, PIN1: row.PIN1, PUK1: row.PUK1,
		ADM1: row.ADM1, ADM2: row.ADM2, SPN: row.SPN, Algorithm: row.Algorithm,
		RotationConstants: row.Rotation, XoringConstants: row.Xoring, NumberOfKeccak: row.NumberOfKeccak,
	}
	var err error
	if len(row.K) > 0 {
		if d.K, err = s.KMS.Decrypt(row.K); err != nil {
			return nil, err
		}
	}
	if len(row.OPc) > 0 {
		if d.OPc, err = s.KMS.Decrypt(row.OPc); err != nil {
			return nil, err
		}
	}
	return d, nil
}
