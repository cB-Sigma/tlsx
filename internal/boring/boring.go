// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package boring stands in for the standard library's crypto/internal/boring
// in the upstream crypto/tls tests that tlsx carries: tlsx is never built
// with BoringCrypto.
package boring

import "crypto/rand"

// Enabled is false: tlsx does not use BoringCrypto.
const Enabled = false

// RandReader is crypto/rand's Reader.
var RandReader = rand.Reader
