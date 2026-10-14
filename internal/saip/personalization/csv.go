package personalization

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CSVSource reads personalization data from a CSV file. The column names are
// mapped to fields through Mapping (e.g. {"iccid":"ICCID","k":"K"}).
type CSVSource struct {
	Path    string
	Mapping map[string]string

	rows []*Data
	pos  int
	err  error
}

// rowKey returns the column name for a logical field.
func (s *CSVSource) rowKey(field string) string {
	if v, ok := s.Mapping[field]; ok {
		return v
	}
	return field
}

func (s *CSVSource) load() error {
	f, err := os.Open(s.Path)
	if err != nil {
		return fmt.Errorf("personalization: open %s: %w", s.Path, err)
	}
	defer func() { _ = f.Close() }()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	records, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("personalization: read %s: %w", s.Path, err)
	}
	if len(records) < 1 {
		return fmt.Errorf("personalization: %s is empty", s.Path)
	}
	header := records[0]
	index := map[string]int{}
	for i, name := range header {
		index[strings.ToLower(strings.TrimSpace(name))] = i
	}
	get := func(rec []string, field string) string {
		col := strings.ToLower(s.rowKey(field))
		i, ok := index[col]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	for _, rec := range records[1:] {
		if len(rec) == 0 {
			continue
		}
		d := &Data{
			ICCID:     get(rec, "iccid"),
			IMSI:      get(rec, "imsi"),
			PIN1:      get(rec, "pin1"),
			PUK1:      get(rec, "puk1"),
			ADM1:      get(rec, "adm1"),
			ADM2:      get(rec, "adm2"),
			SPN:       get(rec, "spn"),
			Algorithm: get(rec, "algorithm"),
		}
		if v := get(rec, "k"); v != "" {
			d.K, err = hex.DecodeString(v)
			if err != nil {
				return fmt.Errorf("personalization: bad K %q: %w", v, err)
			}
		}
		if v := get(rec, "opc"); v != "" {
			d.OPc, err = hex.DecodeString(v)
			if err != nil {
				return fmt.Errorf("personalization: bad OPc %q: %w", v, err)
			}
		}
		if v := get(rec, "rotation"); v != "" {
			d.RotationConstants, err = hex.DecodeString(v)
			if err != nil {
				return fmt.Errorf("personalization: bad rotation %q: %w", v, err)
			}
		}
		if v := get(rec, "xoring"); v != "" {
			d.XoringConstants, err = hex.DecodeString(v)
			if err != nil {
				return fmt.Errorf("personalization: bad xoring %q: %w", v, err)
			}
		}
		// N17 fields.
		if v := get(rec, "mnclen"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || (n != 2 && n != 3) {
				return fmt.Errorf("personalization: bad mncLen %q (want 2 or 3)", v)
			}
			d.MncLen = &n
		}
		if v := get(rec, "sdkeys"); v != "" {
			if err := json.Unmarshal([]byte(v), &d.SdKeys); err != nil {
				return fmt.Errorf("personalization: bad sdKeys JSON: %w", err)
			}
		}
		s.rows = append(s.rows, d)
	}
	return nil
}

// Next implements Source.
func (s *CSVSource) Next() (*Data, error) {
	if s.rows == nil && s.err == nil {
		s.err = s.load()
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.pos >= len(s.rows) {
		return nil, nil
	}
	d := s.rows[s.pos]
	s.pos++
	return d, nil
}

// NewSource builds a Source from a kind ("static", "file", "csv") and path.
func NewSource(kind, path string, mapping map[string]string, static []*Data) (Source, error) {
	switch strings.ToLower(kind) {
	case "", "static":
		return &StaticSource{Items: static}, nil
	case "file", "csv":
		return &CSVSource{Path: path, Mapping: mapping}, nil
	default:
		return nil, fmt.Errorf("personalization: unsupported source kind %q", kind)
	}
}
