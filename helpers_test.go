package verifdocs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Helpers shared by the tests in this package.

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return data
}

func mustUnmarshal(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString: %v", err)
	}
	return decoded
}

// flipBit returns a copy of b with the lowest bit of b[i] flipped.
func flipBit(b []byte, i int) []byte {
	flipped := bytes.Clone(b)
	flipped[i] ^= 0x01
	return flipped
}

// requireNoError fails the test if err is not nil.
func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// requireErrorIs fails the test unless err is not nil and errors.Is(err, want).
func requireErrorIs(t *testing.T, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// requireErrorContains fails the test unless err is not nil and its message
// contains want.
func requireErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want one containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want it to contain %q", err, want)
	}
}

func mustVerifier(t *testing.T, multikey string) SigVerifier {
	t.Helper()
	verifier, err := VerifierFromMultikey(multikey)
	if err != nil {
		t.Fatalf("VerifierFromMultikey: %v", err)
	}
	return verifier
}

// requireSigVerifies fails the test unless sig is a valid signature over data.
func requireSigVerifies(t *testing.T, verifier SigVerifier, data, sig []byte) {
	t.Helper()
	ok, err := verifier.Verify(data, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("verify returned false for a valid signature")
	}
}

// requireSigRejected fails the test unless Verify cleanly rejects sig over data.
func requireSigRejected(t *testing.T, verifier SigVerifier, data, sig []byte) {
	t.Helper()
	ok, err := verifier.Verify(data, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("verify returned true for an invalid signature")
	}
}
