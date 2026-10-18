// secdns-adminauth performs explicit offline, local authentication administration.
// It never opens a record database or contacts an administration listener.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zhouchenh/secDNS/internal/adminauth"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("secdns-adminauth", flag.ContinueOnError)
	f.SetOutput(errOut)
	definition := f.String("definition", "", "Private JSON auth definition file")
	operation := f.String("operation", "", "create, migrate-schema1, enable-human, setup-human, recover-human, cancel-human, issue-agent, cancel-bootstrap, revoke-agent")
	name := f.String("name", "", "Agent display name")
	sc := f.String("scopes", "", "Comma-separated exact scopes")
	expiry := f.String("expires", "", "Optional RFC3339 absolute expiry")
	id := f.String("credential-id", "", "Credential ID for local revocation")
	if f.Parse(args) != nil {
		return 2
	}
	if f.NArg() != 0 || *definition == "" {
		fmt.Fprintln(errOut, "explicit definition and operation required")
		return 2
	}
	fail := func() int {
		fmt.Fprintln(errOut, "authentication administration failed; inspect operation state before retrying")
		return 1
	}
	file, e := os.Open(*definition)
	if e != nil {
		return fail()
	}
	data, e := io.ReadAll(io.LimitReader(file, 16385))
	file.Close()
	if e != nil || len(data) > 16384 {
		return fail()
	}
	var d adminauth.Definition
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || d.Validate() != nil {
		return fail()
	}
	var tail any
	if dec.Decode(&tail) != io.EOF {
		return fail()
	}
	switch *operation {
	case "create":
		if adminauth.CreateKey(d.KeyPath) != nil {
			return fail()
		}
		s, e := adminauth.Create(d.Path, d.KeyPath, d.Identity(), nil)
		if e != nil {
			return fail()
		}
		if s.Close() != nil {
			return fail()
		}
		fmt.Fprintln(out, "Authentication store created; run enable-human explicitly before human setup.")
		return 0
	case "enable-human":
		if adminauth.EnableHumanSchema(d.Path, d.KeyPath, d.Identity(), nil) != nil {
			return fail()
		}
		fmt.Fprintln(out, "Human schema enabled. Create a one-use local setup grant next.")
		return 0
	case "migrate-schema1":
		if adminauth.MigrateSchema1(d.Path, d.KeyPath, d.Identity(), nil) != nil {
			return fail()
		}
		fmt.Fprintln(out, "Authentication schema migrated.")
		return 0
	case "issue-agent", "cancel-bootstrap", "revoke-agent", "setup-human", "recover-human", "cancel-human":
	default:
		return 2
	}
	s, e := adminauth.Open(d.Path, d.KeyPath, d.Identity(), nil)
	if e != nil {
		return fail()
	}
	defer s.Close()
	now := time.Now()
	if *operation == "setup-human" || *operation == "recover-human" {
		grant, e := s.CreateHumanGrant(*operation == "recover-human", now)
		if e != nil {
			return fail()
		}
		if json.NewEncoder(out).Encode(map[string]string{"grant": grant}) != nil {
			return fail()
		}
		return 0
	}
	if *operation == "cancel-human" {
		if s.CancelHumanGrant(now) != nil {
			return fail()
		}
		fmt.Fprintln(out, "Human grant cancelled.")
		return 0
	}
	if *operation == "cancel-bootstrap" {
		if s.CancelBootstrapLocal(now) != nil {
			return fail()
		}
		fmt.Fprintln(out, "Bootstrap grant cancelled.")
		return 0
	}
	if *operation == "revoke-agent" {
		if s.RevokeLocal(*id, now) != nil {
			return fail()
		}
		fmt.Fprintln(out, "Agent credential revoked.")
		return 0
	}
	var scopes []adminauth.Scope
	for _, v := range strings.Split(*sc, ",") {
		scopes = append(scopes, adminauth.Scope(v))
	}
	var expires time.Time
	if *expiry != "" {
		expires, e = time.Parse(time.RFC3339, *expiry)
		if e != nil {
			return fail()
		}
	}
	request := adminauth.CredentialRequest{Name: *name, Scopes: scopes, ExpiresAt: expires}
	if request.Validate(now) != nil {
		return fail()
	}
	grant, e := s.CreateBootstrap(adminauth.BootstrapEnvelope{Scopes: scopes, CredentialExpiresAt: expires}, now)
	if e != nil {
		return fail()
	}
	token, c, e := s.BootstrapIssueAgent(grant, request, now)
	if e != nil {
		return fail()
	}
	// This is the single intentional local secret-output boundary, requested by
	// the operator command. Neither logs nor errors include the returned value.
	if e = json.NewEncoder(out).Encode(map[string]any{"credential_id": c.ID, "credential": token, "scopes": c.Scopes}); e != nil {
		return fail()
	}
	return 0
}
