// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tls13

// ExternalBinderKey derives the binder key of an external PSK (RFC 8446
// 7.1, label "ext binder"); ResumptionBinderKey is the one of a ticket.
// It mirrors Go's ResumptionBinderKey in this package (tls13.go).
func (s *EarlySecret) ExternalBinderKey() []byte {
	return deriveSecret(s.hash, s.secret, "ext binder", nil)
}
