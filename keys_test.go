package verifdocs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/multiformats/go-multibase"
)

// ecdsaJCSVectors are known-answer tests for multikey verification.
//
// P-256 and P-384 are the ecdsa-jcs-2019 vectors from
// https://w3c.github.io/vc-di-ecdsa/#representation-ecdsa-jcs-2019-with-curve-p-256
// and the matching P-384 section. digest is proofHash || credentialHash.
// sig is the raw IEEE P1363 signature (r || s).
//
// That specification does not publish a P-521 vector. The P-521 entry is a
// fixed signature over SHA-512 of the digest.
var ecdsaJCSVectors = []struct {
	name   string
	key    string
	digest string
	sig    string
}{
	{
		name: "P-256",
		key:  "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
		digest: "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec25" +
			"59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
		sig: "f15c3b599eb9b3cad05df9d8e8b39a70a86375833b53743c764ac0a88c4457d6" +
			"0707fd7d073e03d906130631d87803f80a9824dc9939632ba92d418181be9d16",
	},
	{
		name: "P-384",
		key:  "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
		digest: "83e5057817abb0c6872eafeaba1a9e53893c58eeb7414fb6d8aa3fa8c7917f7a" +
			"d4792890b257c598baa17f4fbe6d183c" +
			"3e0be671cc1881035d463158c80921973dab3534d4f8dfacf4ff2725a4115eb7" +
			"18e49d66de0e90e7365cd6062abf2259",
		sig: "8b7462ce62db0c8ff19878c4b3561c49eb71b4a743086b6d5b0eda70ecf0afc5" +
			"a03fd88eb207d66b262ed87fd200a4e8e62716e0b329c032b67726b4b0fc737a" +
			"44c1cefdba2fdccb3ece74cc5845aaa93374455a726f6ee4f5f30da9427f608a",
	},
	{
		name:   "P-521",
		key:    "z2J9gcGqxxSkswmHnEcRBSPvjjquhNTtUbqxv87Mqp7dhaiW4cxuSdb7awhebt7UeeqNoLGA45o72ksBo3FwdGtPaFp89aLn",
		digest: "703532312d646f63756d656e742d646967657374",
		sig: "019c1356656ff259305600d28bd4580aa97e30ea5f45c83bc492f02414d82d07" +
			"183bb9f38f6fb929701b69902e8c79471b531f6e7a6319b35e4f945df62f601d" +
			"29a2015d4c11ffeb93f87aa3a6eb19c583d6dabfeb3709fca7c7901736d9c4d5" +
			"ef530c7d858858eb0afb99c3593601ee7af15eebb5d8a1a84013f47c9a81c1b3" +
			"de73bd20",
	},
}

// Multicodecs for compressed NIST public keys. See the multiformats table.
const (
	codecP256 = 0x1200
	codecP384 = 0x1201
	codecP521 = 0x1202
)

func TestVerifierFromMultikey_VerifiesKnownDigest(t *testing.T) {
	for _, vec := range ecdsaJCSVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			verifier, digest, sig := parseECDSAVector(t, vec.key, vec.digest, vec.sig)

			ok, err := verifier.verify(digest, sig)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Fatal("verify returned false for the known digest")
			}
		})
	}
}

func TestVerifierFromMultikey_RejectsDifferentDigestOrSignature(t *testing.T) {
	for _, vec := range ecdsaJCSVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			verifier, digest, sig := parseECDSAVector(t, vec.key, vec.digest, vec.sig)

			t.Run("digest", func(t *testing.T) {
				tampered := bytes.Clone(digest)
				tampered[0] ^= 0x01
				assertVerifyRejected(t, verifier, tampered, sig)
			})
			t.Run("signature", func(t *testing.T) {
				tampered := bytes.Clone(sig)
				tampered[len(tampered)-1] ^= 0x01
				assertVerifyRejected(t, verifier, digest, tampered)
			})
		})
	}
}

func TestVerifierFromMultikey_UnknownCodec(t *testing.T) {
	// 0xed is the ed25519-pub multicodec, which this parser does not accept.
	key := encodeMultikey(t, 0xed, bytes.Repeat([]byte{0x11}, 32))
	_, err := VerifierFromMultikey(key)
	if err == nil {
		t.Fatal("expected an error for an unknown multicodec")
	}
	if !strings.Contains(err.Error(), "unsupported multicodec") {
		t.Fatalf("error = %q, want an unsupported multicodec error", err)
	}
}

func TestVerifierFromMultikey_WrongKeyLength(t *testing.T) {
	curves := []struct {
		name           string
		codec          uint64
		compressedSize int
	}{
		{"P-256", codecP256, 33},
		{"P-384", codecP384, 49},
		{"P-521", codecP521, 67},
	}
	for _, curve := range curves {
		t.Run(curve.name, func(t *testing.T) {
			t.Parallel()
			for _, delta := range []int{-1, 1} {
				name := "short"
				if delta > 0 {
					name = "long"
				}
				t.Run(name, func(t *testing.T) {
					keyBytes := bytes.Repeat([]byte{0x02}, curve.compressedSize+delta)
					key := encodeMultikey(t, curve.codec, keyBytes)
					_, err := VerifierFromMultikey(key)
					if err == nil {
						t.Fatal("expected an error for the wrong key length")
					}
					if !strings.Contains(err.Error(), "public key length") {
						t.Fatalf("error = %q, want a public key length error", err)
					}
				})
			}
		})
	}
}

func TestVerifierFromMultikey_InvalidCurvePoint(t *testing.T) {
	// x = 7 is inside the field prime of each curve and has no corresponding y.
	curves := []struct {
		name           string
		codec          uint64
		compressedSize int
	}{
		{"P-256", codecP256, 33},
		{"P-384", codecP384, 49},
		{"P-521", codecP521, 67},
	}
	for _, curve := range curves {
		t.Run(curve.name, func(t *testing.T) {
			t.Parallel()
			point := make([]byte, curve.compressedSize)
			point[0] = 0x02
			point[len(point)-1] = 0x07

			key := encodeMultikey(t, curve.codec, point)
			_, err := VerifierFromMultikey(key)
			if err == nil {
				t.Fatal("expected an error for an invalid curve point")
			}
			if !strings.Contains(err.Error(), "curve point") {
				t.Fatalf("error = %q, want a curve point error", err)
			}
		})
	}
}

func parseECDSAVector(t *testing.T, key, digestHex, sigHex string) (SigVerifier, []byte, []byte) {
	t.Helper()
	verifier, err := VerifierFromMultikey(key)
	if err != nil {
		t.Fatalf("VerifierFromMultikey: %v", err)
	}
	return verifier, mustDecodeHex(t, digestHex), mustDecodeHex(t, sigHex)
}

func assertVerifyRejected(t *testing.T, verifier SigVerifier, digest, sig []byte) {
	t.Helper()
	ok, err := verifier.verify(digest, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("verify returned true")
	}
}

func encodeMultikey(t *testing.T, codec uint64, key []byte) string {
	t.Helper()
	prefix := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(prefix, codec)
	encoded, err := multibase.Encode(multibase.Base58BTC, append(prefix[:n], key...))
	if err != nil {
		t.Fatalf("multibase encode: %v", err)
	}
	return encoded
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}
