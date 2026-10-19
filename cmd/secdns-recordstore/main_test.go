package main

import (
	"bytes"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineMigrationCLI(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "records.db")
	var out, errs bytes.Buffer
	args := []string{"-operation", "enable-rrset-mutations", "-database", path, "-ruleset-id", "test", "-lineage-id", "lineage"}
	if run(args, &out, &errs) != 1 {
		t.Fatal("missing accepted")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("created missing file")
	}
	s, e := recordstore.OpenVersionedSQLite(path, recordstore.Enrollment{RulesetID: "test", LineageID: "lineage"})
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if run(args, &out, &errs) != 0 {
		t.Fatal(errs.String())
	}
	if run(args, &out, &errs) != 1 {
		t.Fatal("repeated migration")
	}
	if run([]string{"-operation", "other"}, &out, &errs) != 2 {
		t.Fatal("unknown operation")
	}
}
