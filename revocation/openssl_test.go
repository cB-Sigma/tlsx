// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// OPENSSL INTEROP TEST: it runs when an OpenSSL 3 "openssl" is on PATH
// and TLSX_SKIP_INTEROP is not set (the CI interop job runs it and fails
// on a skip), and shows that CRLs made by OpenSSL's "ca -gencrl" parse
// and apply.

func opensslBin(t *testing.T) string {
	t.Helper()
	if os.Getenv("TLSX_SKIP_INTEROP") != "" {
		t.Skip("OPENSSL INTEROP: TLSX_SKIP_INTEROP is set")
	}
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OPENSSL INTEROP: openssl not on PATH")
	}
	out, err := exec.Command(p, "version").Output()
	if err != nil || !bytes.HasPrefix(out, []byte("OpenSSL 3.")) {
		t.Skipf("OPENSSL INTEROP: %s is not OpenSSL 3 (%q)", p, bytes.TrimSpace(out))
	}
	return p
}

func TestOpenSSLCRL(t *testing.T) {
	bin := opensslBin(t)
	p := newPKI(t)
	dir := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.inter.key)
	if err != nil {
		t.Fatal(err)
	}
	pemFile := func(name, typ string, der []byte) string {
		return writeFile(t, dir, name, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
	}
	caCert := pemFile("ca.pem", "CERTIFICATE", p.inter.cert.Raw)
	caKey := pemFile("ca.key", "PRIVATE KEY", keyDER)
	revoked := pemFile("revoked.pem", "CERTIFICATE", p.bad.Raw)
	writeFile(t, dir, "index.txt", nil)
	writeFile(t, dir, "crlnumber", []byte("1A\n"))
	cnf := writeFile(t, dir, "ca.cnf", []byte(fmt.Sprintf(`[ ca ]
default_ca = test_ca
[ test_ca ]
database = %[1]s/index.txt
crlnumber = %[1]s/crlnumber
certificate = %[2]s
private_key = %[3]s
default_md = sha256
default_crl_days = 2
crl_extensions = crl_ext
[ crl_ext ]
authorityKeyIdentifier = keyid:always
`, dir, caCert, caKey)))
	run := func(args ...string) {
		t.Helper()
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	run("ca", "-config", cnf, "-revoke", revoked, "-crl_reason", "keyCompromise")
	crlPath := filepath.Join(dir, "crl.pem")
	run("ca", "-config", cnf, "-gencrl", "-out", crlPath)

	c := mustNew(t, Config{DisableRefresh: true, Sources: []Source{{Issuer: p.inter.cert, File: crlPath}}})
	st := c.Status()[0]
	if st.State != StateOK || st.Number == nil || st.Number.Int64() != 0x1a || st.Revoked != 1 {
		t.Fatalf("status of the OpenSSL CRL = %+v", st)
	}
	var re *RevokedError
	if err := c.CheckChain(p.chain(p.bad)); !errors.As(err, &re) || re.Reason != 1 {
		t.Fatalf("revoked certificate: got %v", err)
	}
	if err := c.CheckChain(p.chain(p.good)); err != nil {
		t.Fatalf("unrevoked certificate: %v", err)
	}
}
