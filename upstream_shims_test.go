// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
)

// Test-only parts of the upstream shims (upstream_shims.go).

func (fipsShim) Force()              {}
func (fipsShim) TestingOnlyAbandon() {}

func (byteorderShim) BEUint16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

// isFIPSVersion is only asked in FIPS mode, which tlsx does not have.
func isFIPSVersion(uint16) bool { return false }

// isTLSXSuite reports a cipher suite tlsx adds (the upstream tests check
// upstream's lists and recordings).
func isTLSXSuite(id uint16) bool {
	_, ok := tlsxSuiteNames[id]
	return ok
}

// testConfigFIPS140 is declared in upstream's fips140_test.go, which tlsx
// does not carry (no FIPS mode); upstream's TestMain still fills it.
var testConfigFIPS140 *Config

// internalrand stands in for crypto/internal/rand, which one upstream
// benchmark uses to make the handshake's randomness fixed.
var internalrand internalRandShim

type internalRandShim struct{}

// SetTestingReader replaces crypto/rand.Reader (nil restores it).
func (internalRandShim) SetTestingReader(r io.Reader) {
	if r == nil {
		cryptorand.Reader = savedRandReader
		return
	}
	cryptorand.Reader = r
}

var savedRandReader = cryptorand.Reader

// LEPutUint64 is used by the BoGo shim for the shim ID.
func (byteorderShim) LEPutUint64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
