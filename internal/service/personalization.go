package service

import (
	"encoding/json"
	"errors"
	"fmt"

	"rsp42/internal/kms"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
)

// PersonalizationStore is the persistence subset used by PersonalizationService.
type PersonalizationStore interface {
	GetByICCID(tenant, iccid string) (*store.Personalization, error)
	GetByIMSI(tenant, imsi string) (*store.Personalization, error)
	Upsert(p *store.Personalization) error
	Delete(tenant, iccid string) error
	List() ([]*store.Personalization, error)
	ListPage(iccidPrefix, tenant string, limit, offset int) ([]*store.Personalization, int, error)
	ReservePair(tenant, iccid string) (string, error)
	UnbindPair(tenant, iccid string) error
	CountUnbound(tenant string) (int, error)
}

// PersonalizationResolver resolves a profile's personalization values. The IMSI
// is consulted only when no row is bound to the ICCID, which is what makes an
// "IMSI + K/OPc" credentials pool usable before the ICCID is known.
type PersonalizationResolver interface {
	Resolve(tenant, iccid, imsi string) (*personalization.Data, error)
}

// PersonalizationService persists per-tenant personalization, encrypting K/OPc
// at rest with the KMS key-encryption key.
type PersonalizationService struct {
	Repo PersonalizationStore
	KMS  kms.Provider
}

// NewPersonalizationService builds a PersonalizationService.
func NewPersonalizationService(repo PersonalizationStore, provider kms.Provider) *PersonalizationService {
	return &PersonalizationService{Repo: repo, KMS: provider}
}

// Resolve returns the personalization for a profile, or (nil, nil) when none is
// registered. The ICCID binding wins; a tenant credentials-pool entry is used
// when the IMSI is known.
func (s *PersonalizationService) Resolve(tenant, iccid, imsi string) (*personalization.Data, error) {
	if iccid != "" {
		row, err := s.Repo.GetByICCID(tenant, iccid)
		switch {
		case err == nil:
			return s.decrypt(row)
		case !errors.Is(err, store.ErrNotFound):
			return nil, err
		}
	}
	if imsi != "" {
		row, err := s.Repo.GetByIMSI(tenant, imsi)
		switch {
		case err == nil:
			d, derr := s.decrypt(row)
			if derr != nil {
				return nil, derr
			}
			// The row is a credentials-pool entry; the download order owns the
			// ICCID, so the binding is surfaced here.
			if d.ICCID == "" {
				d.ICCID = iccid
			}
			return d, nil
		case !errors.Is(err, store.ErrNotFound):
			return nil, err
		}
	}
	return nil, nil
}

// Put encrypts K/OPc and stores the record under the given tenant ("" is the
// platform default). An empty ICCID stores a credentials-pool entry keyed by
// IMSI.
func (s *PersonalizationService) Put(tenant string, d *personalization.Data) error {
	if d.ICCID == "" && d.IMSI == "" {
		return fmt.Errorf("personalization: either iccid or imsi is required")
	}
	var plmn, patches string
	if len(d.PLMN) > 0 {
		b, err := json.Marshal(d.PLMN)
		if err != nil {
			return err
		}
		plmn = string(b)
	}
	if len(d.FilePatches) > 0 {
		b, err := json.Marshal(d.FilePatches)
		if err != nil {
			return err
		}
		patches = string(b)
	}
	var acc *int64
	if d.ACC != nil {
		v := int64(*d.ACC)
		acc = &v
	}
	row := &store.Personalization{
		TenantID: tenant, ICCID: d.ICCID, IMSI: d.IMSI,
		PIN1: d.PIN1, PUK1: d.PUK1, ADM1: d.ADM1, ADM2: d.ADM2,
		SPN: d.SPN, Algorithm: d.Algorithm,
		Rotation: d.RotationConstants, Xoring: d.XoringConstants, NumberOfKeccak: d.NumberOfKeccak,
		PLMN: plmn, MSISDN: d.MSISDN, ACC: acc, FilePatches: patches,
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

// ReservePair binds the tenant's lowest unbound credentials-pool entry to an
// ICCID and returns its IMSI. It returns ("", nil) when the tenant has no
// unbound credentials (the pairing is then simply absent).
func (s *PersonalizationService) ReservePair(tenant, iccid string) (string, error) {
	imsi, err := s.Repo.ReservePair(tenant, iccid)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return imsi, err
}

// UnbindPair releases a credentials-pool entry back to the unbound state.
func (s *PersonalizationService) UnbindPair(tenant, iccid string) error {
	return s.Repo.UnbindPair(tenant, iccid)
}

// CountUnbound reports how many credentials-pool entries a tenant has left.
func (s *PersonalizationService) CountUnbound(tenant string) (int, error) {
	return s.Repo.CountUnbound(tenant)
}

// Delete removes a record bound to an ICCID.
func (s *PersonalizationService) Delete(tenant, iccid string) error {
	return s.Repo.Delete(tenant, iccid)
}

// List returns all records (decrypted).
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
// prefix and tenant) plus the total count.
func (s *PersonalizationService) ListPage(iccidPrefix, tenant string, limit, offset int) ([]*personalization.Data, int, error) {
	rows, total, err := s.Repo.ListPage(iccidPrefix, tenant, limit, offset)
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
func (s *PersonalizationService) Import(tenant, kind, path string, mapping map[string]string, static []*personalization.Data) (int, error) {
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
		if d.ICCID == "" && d.IMSI == "" {
			return n, fmt.Errorf("personalization import: row %d has neither ICCID nor IMSI", n+1)
		}
		if err := s.Put(tenant, d); err != nil {
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
		MSISDN: row.MSISDN,
	}
	if row.PLMN != "" {
		if err := json.Unmarshal([]byte(row.PLMN), &d.PLMN); err != nil {
			return nil, fmt.Errorf("personalization: corrupt plmn for %q: %w", row.ICCID, err)
		}
	}
	if row.FilePatches != "" {
		if err := json.Unmarshal([]byte(row.FilePatches), &d.FilePatches); err != nil {
			return nil, fmt.Errorf("personalization: corrupt file patches for %q: %w", row.ICCID, err)
		}
	}
	if row.ACC != nil {
		v := uint16(*row.ACC)
		d.ACC = &v
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
