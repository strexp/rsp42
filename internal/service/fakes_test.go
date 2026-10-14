package service

import (
	"fmt"
	"time"

	"rsp42/internal/rsp"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
)

// This file holds the shared in-memory fakes that let the service layer be
// exercised through its consumer-defined interfaces only (TODO.md §3.5). The
// services must keep working when nothing but these fakes is injected, which is
// the DIP regression: no service reaches for a concrete SQLite repository.

// fakeProfileStore is an in-memory ProfileStore + ProfileCreator.
type fakeProfileStore struct {
	byICCID map[string]*store.Profile
	nextID  int64

	Gets     int
	Updates  int
	Creates  int
	Deletes  int
	FailUpd  error
	FailNew  error
	FailGets error
}

func newFakeProfileStore(profiles ...*store.Profile) *fakeProfileStore {
	f := &fakeProfileStore{byICCID: map[string]*store.Profile{}}
	for _, p := range profiles {
		f.put(p)
	}
	return f
}

func (f *fakeProfileStore) put(p *store.Profile) {
	if p.ID == 0 {
		f.nextID++
		p.ID = f.nextID
	}
	f.byICCID[p.ICCID] = p
}

func (f *fakeProfileStore) GetByICCID(iccid string) (*store.Profile, error) {
	f.Gets++
	if f.FailGets != nil {
		return nil, f.FailGets
	}
	p, ok := f.byICCID[iccid]
	if !ok {
		return nil, fmt.Errorf("fake: profile %s: %w", iccid, store.ErrNotFound)
	}
	return p, nil
}

func (f *fakeProfileStore) GetByMatchingID(matchingID string) (*store.Profile, error) {
	for _, p := range f.byICCID {
		if p.MatchingID == matchingID {
			return p, nil
		}
	}
	return nil, fmt.Errorf("fake: matching id %s: %w", matchingID, store.ErrNotFound)
}

func (f *fakeProfileStore) GetByID(id int64) (*store.Profile, error) {
	for _, p := range f.byICCID {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, fmt.Errorf("fake: id %d: %w", id, store.ErrNotFound)
}

func (f *fakeProfileStore) Update(p *store.Profile) error {
	f.Updates++
	if f.FailUpd != nil {
		return f.FailUpd
	}
	f.put(p)
	return nil
}

func (f *fakeProfileStore) Delete(iccid string) error {
	f.Deletes++
	if _, ok := f.byICCID[iccid]; !ok {
		return store.ErrNotFound
	}
	delete(f.byICCID, iccid)
	return nil
}

func (f *fakeProfileStore) Create(p *store.Profile) (int64, error) {
	f.Creates++
	if f.FailNew != nil {
		return 0, f.FailNew
	}
	if _, exists := f.byICCID[p.ICCID]; exists {
		return 0, fmt.Errorf("fake: duplicate ICCID %s", p.ICCID)
	}
	f.put(p)
	return p.ID, nil
}

// fakeUPPStore is an in-memory UPPStore. SelectBest implements the registry
// semantics: the greatest active template not exceeding any supported version.
type fakeUPPStore struct {
	templates map[string]*store.UPPTemplate // tenant + "/" + name
	Selects   int
}

func newFakeUPPStore(templates ...*store.UPPTemplate) *fakeUPPStore {
	f := &fakeUPPStore{templates: map[string]*store.UPPTemplate{}}
	for _, t := range templates {
		f.templates[t.TenantID+"/"+t.Name] = t
	}
	return f
}

func (f *fakeUPPStore) GetForTenant(tenant, name string) (*store.UPPTemplate, error) {
	if t, ok := f.templates[tenant+"/"+name]; ok {
		return t, nil
	}
	if t, ok := f.templates["/"+name]; ok && tenant != "" {
		return t, nil
	}
	return nil, fmt.Errorf("fake: upp %s: %w", name, store.ErrNotFound)
}

func (f *fakeUPPStore) SelectBestFor(tenant string, versions []rsp.Version) (*store.UPPTemplate, error) {
	f.Selects++
	if len(versions) == 0 {
		return nil, store.ErrNotFound
	}
	var best *store.UPPTemplate
	for _, t := range f.templates {
		if t.TenantID != tenant && t.TenantID != "" {
			continue
		}
		if !t.Active {
			continue
		}
		v := rsp.Version{Major: t.SAIPMajor, Minor: t.SAIPMinor}
		supported := false
		for _, s := range versions {
			if v.Compare(s) <= 0 {
				supported = true
				break
			}
		}
		if !supported {
			continue
		}
		if best == nil || v.Compare(rsp.Version{Major: best.SAIPMajor, Minor: best.SAIPMinor}) > 0 ||
			(v == rsp.Version{Major: best.SAIPMajor, Minor: best.SAIPMinor} && t.Name < best.Name) {
			best = t
		}
	}
	if best == nil {
		return nil, store.ErrNotFound
	}
	return best, nil
}

// fakeTenantLookup implements TenantLookup.
type fakeTenantLookup struct {
	defaultUPP map[string]string
	callback   map[string]string
}

func (f fakeTenantLookup) DefaultUPPForTenant(tenant string) (string, error) {
	return f.defaultUPP[tenant], nil
}

func (f fakeTenantLookup) CallbackURLForTenant(tenant string) (string, error) {
	return f.callback[tenant], nil
}

// fakePersoResolver implements PersonalizationResolver.
type fakePersoResolver struct {
	byKey map[string]*personalization.Data
	Calls int
}

func newFakePersoResolver() *fakePersoResolver {
	return &fakePersoResolver{byKey: map[string]*personalization.Data{}}
}

func (f *fakePersoResolver) Resolve(tenant, iccid, imsi string) (*personalization.Data, error) {
	f.Calls++
	if d, ok := f.byKey[tenant+"/"+iccid]; ok {
		return d, nil
	}
	if d, ok := f.byKey[tenant+"/imsi/"+imsi]; ok {
		return d, nil
	}
	return nil, nil
}

// fakeICCIDPool implements ICCIDPool for the allocation tests.
type fakeICCIDPool struct {
	available []string
	state     map[string]string
	Reserves  int
	// FailClaim / FailSetState inject a storage failure into the pool path.
	FailClaim    error
	FailSetState error
}

func newFakeICCIDPool(available ...string) *fakeICCIDPool {
	return &fakeICCIDPool{available: available, state: map[string]string{}}
}

func (f *fakeICCIDPool) Reserve(tenant, eid, reference string, ttl time.Duration) (string, error) {
	f.Reserves++
	if len(f.available) == 0 {
		return "", store.ErrNotFound
	}
	iccid := f.available[0]
	f.available = f.available[1:]
	f.state[iccid] = "allocated"
	return iccid, nil
}

func (f *fakeICCIDPool) Claim(iccid string, profileID int64) error {
	if f.FailClaim != nil {
		return f.FailClaim
	}
	f.state[iccid] = "allocated"
	return nil
}

func (f *fakeICCIDPool) SetState(iccid, state, note string) error {
	if f.FailSetState != nil {
		return f.FailSetState
	}
	f.state[iccid] = state
	return nil
}

func (f *fakeICCIDPool) State(iccid string) (string, error) {
	s, ok := f.state[iccid]
	if !ok {
		return "", store.ErrNotFound
	}
	return s, nil
}

// fakeEventStore implements EventStore for the SM-DS event tests, with failure
// injection so the storage-error paths are distinguishable from "not found".
type fakeEventStore struct {
	byKey    map[string]*store.EventRecord
	nextID   int64
	FailGet  error
	FailInse error
}

func newFakeEventStore() *fakeEventStore {
	return &fakeEventStore{byKey: map[string]*store.EventRecord{}}
}

func eventKey(eid, eventID, callerOID string) string {
	return eid + "\x00" + eventID + "\x00" + callerOID
}

func (f *fakeEventStore) GetByKey(eid, eventID, callerOID string) (*store.EventRecord, error) {
	if f.FailGet != nil {
		return nil, f.FailGet
	}
	rec, ok := f.byKey[eventKey(eid, eventID, callerOID)]
	if !ok {
		return nil, store.ErrNotFound
	}
	return rec, nil
}

func (f *fakeEventStore) Insert(e *store.EventRecord) (int64, error) {
	if f.FailInse != nil {
		return 0, f.FailInse
	}
	k := eventKey(e.EID, e.EventID, e.CallerOID)
	if _, exists := f.byKey[k]; exists {
		return 0, store.ErrEventIDInUse
	}
	f.nextID++
	e.ID = f.nextID
	f.byKey[k] = e
	return e.ID, nil
}

func (f *fakeEventStore) SoftDelete(id int64) (bool, error) {
	for _, rec := range f.byKey {
		if rec.ID == id && rec.DeletedAt == nil {
			now := time.Now().UTC()
			rec.DeletedAt = &now
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeEventStore) HardDelete(id int64) error {
	for k, rec := range f.byKey {
		if rec.ID == id {
			delete(f.byKey, k)
		}
	}
	return nil
}

func (f *fakeEventStore) ListByEID(string) ([]*store.EventRecord, error) { return nil, nil }

func (f *fakeEventStore) ListByEIDEventID(string, string) ([]*store.EventRecord, error) {
	return nil, nil
}

func (f *fakeEventStore) ListAll() ([]*store.EventRecord, error) {
	out := make([]*store.EventRecord, 0, len(f.byKey))
	for _, rec := range f.byKey {
		out = append(out, rec)
	}
	return out, nil
}

func (f *fakeEventStore) GCExpired(time.Time) (int64, error) { return 0, nil }
