package verifdocs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"math/big"
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

// Multicodecs from the multiformats table.
const (
	codecP256    = 0x1200
	codecP384    = 0x1201
	codecP521    = 0x1202
	codecEd25519 = 0xed
	codecX25519  = 0xec
)

// eddsa-jcs-2022 vector from Appendix B.3 of
// https://w3c.github.io/vc-di-eddsa/#representation-eddsa-jcs-2022
// digest is SHA-256(canonical proof) || SHA-256(canonical document).
// sig is the raw 64-byte Ed25519 signature over that concatenation.
const (
	ed25519PublicKey = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
	ed25519Digest    = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db" +
		"59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
	ed25519Sig = "407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b803" +
		"51da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808"
)

func TestVerifierFromMultikey_VerifiesKnownDigest(t *testing.T) {
	for _, vec := range ecdsaJCSVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			verifier, digest, sig := parseMultikeyVector(t, vec.key, vec.digest, vec.sig)

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
			verifier, digest, sig := parseMultikeyVector(t, vec.key, vec.digest, vec.sig)

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

func TestVerifierFromMultikey_Ed25519VerifiesKnownDigest(t *testing.T) {
	verifier, digest, sig := parseEd25519Vector(t)
	if verifier.sigType() != SigType_EDDSA {
		t.Fatalf("sigType = %v, want EdDSA", verifier.sigType())
	}

	ok, err := verifier.verify(digest, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("verify returned false for the known digest")
	}
}

func TestEDDSAVerifier_HashIsSHA256(t *testing.T) {
	verifier, _, _ := parseEd25519Vector(t)
	msg := []byte("canonical-bytes")
	sum := sha256.Sum256(msg)
	if !bytes.Equal(verifier.hash(msg), sum[:]) {
		t.Fatalf("hash = %x, want SHA-256 %x", verifier.hash(msg), sum[:])
	}
}

func TestVerifierFromMultikey_Ed25519RejectsDifferentDigestOrSignature(t *testing.T) {
	verifier, digest, sig := parseEd25519Vector(t)

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
	t.Run("noncanonical signature", func(t *testing.T) {
		// RFC 8032 rejects signatures whose final byte has the top bits set.
		tampered := bytes.Clone(sig)
		tampered[63] |= 0x80
		assertVerifyRejected(t, verifier, digest, tampered)
	})
}

func TestEDDSAVerifier_WrongSignatureLength(t *testing.T) {
	verifier, digest, sig := parseEd25519Vector(t)
	cases := []struct {
		name string
		sig  []byte
	}{
		{name: "empty", sig: nil},
		{name: "short", sig: sig[:ed25519.SignatureSize-1]},
		{name: "long", sig: append(bytes.Clone(sig), 0x00)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := verifier.verify(digest, tt.sig)
			if ok {
				t.Fatal("verify returned true")
			}
			if err == nil {
				t.Fatal("expected a signature size error")
			}
			if !strings.Contains(err.Error(), "wrong signature size") {
				t.Fatalf("error = %q, want a signature size error", err)
			}
		})
	}
}

func TestVerifierFromMultikey_Ed25519RejectsOtherKeys(t *testing.T) {
	_, digest, sig := parseEd25519Vector(t)

	t.Run("different key", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x07}, ed25519.SeedSize)))
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		verifier, err := VerifierFromMultikey(encodeMultikey(t, codecEd25519, pub))
		if err != nil {
			t.Fatalf("VerifierFromMultikey: %v", err)
		}
		assertVerifyRejected(t, verifier, digest, sig)
	})
	t.Run("off curve", func(t *testing.T) {
		// 32 0xff bytes is not a canonical edwards25519 point.
		// Parsing accepts any 32-byte key; verification rejects it.
		verifier, err := VerifierFromMultikey(encodeMultikey(t, codecEd25519, bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)))
		if err != nil {
			t.Fatalf("VerifierFromMultikey: %v", err)
		}
		assertVerifyRejected(t, verifier, digest, sig)
	})
}

func TestVerifierFromMultikey_UnknownCodec(t *testing.T) {
	// x25519-pub is a key-agreement codec, not a signature key.
	key := encodeMultikey(t, codecX25519, bytes.Repeat([]byte{0x11}, 32))
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
		name    string
		codec   uint64
		keySize int
	}{
		{"P-256", codecP256, 33},
		{"P-384", codecP384, 49},
		{"P-521", codecP521, 67},
		{"Ed25519", codecEd25519, ed25519.PublicKeySize},
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
					keyBytes := bytes.Repeat([]byte{0x02}, curve.keySize+delta)
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

func TestVerifierFromMultikey_InvalidEncoding(t *testing.T) {
	_, err := VerifierFromMultikey("not-a-multikey")
	if err == nil {
		t.Fatal("expected an error for an invalid multikey")
	}
}

func TestECDSASigner_SignsWithAllCurves(t *testing.T) {
	msg := []byte("canonical-bytes")
	curves := []struct {
		name   string
		curve  elliptic.Curve
		sigLen int
		hash   func([]byte) []byte
	}{
		{
			name:   "P-256",
			curve:  elliptic.P256(),
			sigLen: 64,
			hash: func(data []byte) []byte {
				sum := sha256.Sum256(data)
				return sum[:]
			},
		},
		{
			name:   "P-384",
			curve:  elliptic.P384(),
			sigLen: 96,
			hash: func(data []byte) []byte {
				sum := sha512.Sum384(data)
				return sum[:]
			},
		},
		{
			name:   "P-521",
			curve:  elliptic.P521(),
			sigLen: 132,
			hash: func(data []byte) []byte {
				sum := sha512.Sum512(data)
				return sum[:]
			},
		},
	}
	for _, curve := range curves {
		t.Run(curve.name, func(t *testing.T) {
			t.Parallel()
			signer, err := GenerateECDSASigner(curve.curve)
			if err != nil {
				t.Fatalf("GenerateECDSASigner: %v", err)
			}
			if signer.sigType() != SigType_ECDSA {
				t.Fatalf("sigType = %v, want ECDSA", signer.sigType())
			}

			digest := curve.hash(msg)
			if !bytes.Equal(signer.hash(msg), digest) {
				t.Fatalf("hash = %x, want %x", signer.hash(msg), digest)
			}

			sig, err := signer.sign(msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if len(sig) != curve.sigLen {
				t.Fatalf("signature length = %d, want %d", len(sig), curve.sigLen)
			}

			keySize := curve.sigLen / 2
			r := new(big.Int).SetBytes(sig[:keySize])
			s := new(big.Int).SetBytes(sig[keySize:])
			if !ecdsa.Verify(&signer.signKey.PublicKey, digest, r, s) {
				t.Fatal("signature did not verify")
			}

			// Check that the verifier interface works too.
			b, err := signer.verifier().verify(msg, sig)
			if err != nil {
				t.Fatalf("Error verifying sig: %s", err)
			}
			if !b {
				t.Fatal("Verifier failed to verify sig")
			}

			tampered := bytes.Clone(msg)
			tampered[0] ^= 0x01
			if ecdsa.Verify(&signer.signKey.PublicKey, curve.hash(tampered), r, s) {
				t.Fatal("signature verified a different message")
			}

			b, err = signer.verifier().verify(tampered, sig)
			if err != nil {
				t.Fatalf("Error verifying tampered sig: %s", err)
			}
			if b {
				t.Fatal("Verifier verified a different message")
			}
		})
	}
}

func TestECDSASigner_InvalidSigningKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// crypto/ecdsa rejects a scalar that is outside 1..N-1.
	orderBits := uint(priv.Params().N.BitLen())
	cases := []struct {
		name string
		d    *big.Int
	}{
		{name: "zero", d: big.NewInt(0)},
		{name: "negative", d: big.NewInt(-1)},
		{name: "too large", d: new(big.Int).Lsh(big.NewInt(1), orderBits)},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			key := *priv
			key.D = tt.d
			signer := ECDSASigner{signKey: key}

			sig, err := signer.sign([]byte("canonical-bytes"))
			if err == nil {
				t.Fatal("expected an error for an invalid signing key")
			}
			if len(sig) != 0 {
				t.Fatalf("signature = %x, want none", sig)
			}
			if !strings.Contains(err.Error(), "Error signing") || !strings.Contains(err.Error(), "private key scalar") {
				t.Fatalf("error = %q, want a signing error for an invalid scalar", err)
			}
		})
	}
}

func parseEd25519Vector(t *testing.T) (SigVerifier, []byte, []byte) {
	t.Helper()
	return parseMultikeyVector(t, ed25519PublicKey, ed25519Digest, ed25519Sig)
}

func parseMultikeyVector(t *testing.T, key, digestHex, sigHex string) (SigVerifier, []byte, []byte) {
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
