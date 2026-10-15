// Package archcheck holds no production code. Its only file is a test that
// pins the dependency direction and the third-party containment rules recorded
// in docs/architecture.md, so a structural regression fails `go test` instead
// of being noticed in review.
//
// The rules are checked statically over the import clauses (go/parser,
// ImportsOnly), so the test needs no build, no network and no build tags.
package archcheck

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// module is the module path declared in go.mod.
const module = "rsp42"

// skipDirs are directories that hold no build source (or hold a separate,
// reference-only tree) and must not be scanned.
var skipDirs = map[string]bool{
	".git": true, ".github": true, "bin": true, "refs": true, "testdata": true,
	"deploy": true, "scripts": true, "docs": true, "config": true, "db": true,
}

// leafPackages import nothing else from this module. They hold value types and
// primitives that every layer may use, so an import out of a leaf inverts the
// dependency direction.
var leafPackages = map[string]bool{
	"internal/asn1":    true,
	"internal/iccid":   true,
	"internal/saipver": true,
	"internal/kms":     true,
	"internal/logging": true,
	"internal/metrics": true,
	"internal/version": true,
}

// deniedEdges are dependency edges that must not exist. Each entry states the
// layer rule it enforces; the field is only documentation for the failure
// message.
var deniedEdges = []struct {
	from, to, why string
}{
	// The persistence layer is below the protocol codecs: a comparable pair or
	// a version order is not a wire concern (docs/architecture.md).
	{"internal/store", "internal/rsp", "store must not depend on the SGP.22 codec"},
	{"internal/config", "internal/rsp", "config must not depend on the SGP.22 codec"},

	// Nothing below imports anything above.
	{"internal/store", "internal/service", "store is below service"},
	{"internal/store", "internal/api", "store is below api"},
	{"internal/config", "internal/service", "config is below service"},
	{"internal/config", "internal/api", "config is below api"},
	{"internal/config", "internal/store", "config does not depend on persistence"},
	{"internal/rsp", "internal/service", "rsp is below service"},
	{"internal/rsp", "internal/api", "rsp is below api"},
	{"internal/rsp", "internal/store", "rsp is below store"},
	{"internal/saip", "internal/service", "saip is below service"},
	{"internal/saip", "internal/api", "saip is below api"},
	{"internal/crypto", "internal/service", "crypto is below service"},
	{"internal/crypto", "internal/api", "crypto is below api"},
	{"internal/iccid", "internal/rsp", "iccid is a leaf below the codec"},
	{"internal/iccid", "internal/store", "iccid is a leaf below persistence"},
}

// bertlvImporters are the only files allowed to import the BER-TLV library.
// internal/asn1/construct.go is the single adapter and tools.go is the
// build-tagged dependency pin, which is never compiled into a binary.
var bertlvImporters = map[string]bool{
	"internal/asn1/construct.go": true,
	"tools.go":                   true,
}

const bertlvPath = "github.com/euicc-go/bertlv"

// sourceFile is one parsed Go file.
type sourceFile struct {
	// relPath is the file path relative to the module root, slash-separated.
	relPath string
	// pkgDir is the directory relative to the module root, slash-separated
	// ("." for the module root itself).
	pkgDir string
	// isTest reports whether the file is a _test.go file.
	isTest bool
	// imports are the module-relative import paths ("internal/cert").
	imports []string
}

// modulePath converts an import path to its module-relative form, or reports
// false when the import is not from this module.
func modulePath(imp string) (string, bool) {
	if imp == module {
		return "", true
	}
	prefix := module + "/"
	if !strings.HasPrefix(imp, prefix) {
		return "", false
	}
	return strings.TrimPrefix(imp, prefix), true
}

// scan parses every Go file under the module root.
func scan(t *testing.T) []sourceFile {
	t.Helper()

	root, err := findRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	var files []sourceFile
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			// A file that does not parse is a compile error; report it here so
			// the failure is attributed to this test rather than to a walk.
			t.Errorf("parse %s: %v", rel, err)
			return nil
		}
		sf := sourceFile{
			relPath: rel,
			pkgDir:  filepath.ToSlash(filepath.Dir(rel)),
			isTest:  strings.HasSuffix(rel, "_test.go"),
		}
		for _, spec := range f.Imports {
			imp := strings.Trim(spec.Path.Value, `"`)
			if mp, ok := modulePath(imp); ok {
				sf.imports = append(sf.imports, mp)
			}
			if imp == bertlvPath {
				sf.imports = append(sf.imports, bertlvPath)
			}
		}
		files = append(files, sf)
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Go files found; the scan root is wrong")
	}
	return files
}

// findRoot walks up from the working directory until it finds go.mod.
func findRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// TestNoDeniedDependencyEdges enforces the layer rules above.
func TestNoDeniedDependencyEdges(t *testing.T) {
	for _, f := range scan(t) {
		for _, imp := range f.imports {
			if imp == bertlvPath {
				continue
			}
			for _, rule := range deniedEdges {
				if f.pkgDir == rule.from && imp == rule.to {
					t.Errorf("%s: %s imports %s: %s",
						f.relPath, rule.from, rule.to, rule.why)
				}
			}
		}
	}
}

// TestLeafPackagesStayLeaves enforces that a leaf package imports only other
// leaf packages, so nothing below can be dragged upward.
func TestLeafPackagesStayLeaves(t *testing.T) {
	for _, f := range scan(t) {
		if !leafPackages[f.pkgDir] {
			continue
		}
		for _, imp := range f.imports {
			if imp == bertlvPath || leafPackages[imp] {
				continue
			}
			t.Errorf("%s: leaf package %s must not import %s",
				f.relPath, f.pkgDir, imp)
		}
	}
}

// TestTestutilIsTestOnly enforces that internal/testutil stays out of the
// binary: only _test.go files may import it or its subpackages.
func TestTestutilIsTestOnly(t *testing.T) {
	const testutil = "internal/testutil"
	for _, f := range scan(t) {
		if f.isTest {
			continue
		}
		for _, imp := range f.imports {
			if imp == testutil || strings.HasPrefix(imp, testutil+"/") {
				t.Errorf("%s: non-test file imports %s, which must not be linked into the binary",
					f.relPath, imp)
			}
		}
	}
}

// TestBertlvIsContained enforces that the BER-TLV library is imported by the
// single adapter file only, so replacing the library stays a one-package change.
func TestBertlvIsContained(t *testing.T) {
	for _, f := range scan(t) {
		for _, imp := range f.imports {
			if imp != bertlvPath {
				continue
			}
			if !bertlvImporters[f.relPath] {
				t.Errorf("%s imports %s; only %v may do so",
					f.relPath, bertlvPath, keys(bertlvImporters))
			}
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
