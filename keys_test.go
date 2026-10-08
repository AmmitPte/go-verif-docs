package verifdocs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/nuts-foundation/go-did/did"
)

// --- Multikey verifiers ---

// keyVector is a Multikey public key and a known signature made with it.
type keyVector struct {
	name    string
	key     string // Multikey
	sigType SigType
	data    string // hex; the data that was signed
	sig     string // hex
}

// parse returns a verifier for the key, and the decoded data and signature.
func (v keyVector) parse(t *testing.T) (SigVerifier, []byte, []byte) {
	t.Helper()
	return mustVerifier(t, v.key), mustDecodeHex(t, v.data), mustDecodeHex(t, v.sig)
}

// multikeyVectors has a known signature for each supported key type. The
// P-256, P-384 and Ed25519 entries are the W3C vectors' keys and signatures,
// where the signed data is the credential's hash data. No published vector
// uses P-521, so that entry signs the ASCII bytes "p521-document-digest".
var multikeyVectors = []keyVector{
	{name: "P-256", key: vectorP256.publicKey, sigType: SigTypeECDSA, data: vectorP256.hashData, sig: vectorP256.signature},
	{name: "P-384", key: vectorP384.publicKey, sigType: SigTypeECDSA, data: vectorP384.hashData, sig: vectorP384.signature},
	{
		name:    "P-521",
		key:     "z2J9gcGqxxSkswmHnEcRBSPvjjquhNTtUbqxv87Mqp7dhaiW4cxuSdb7awhebt7UeeqNoLGA45o72ksBo3FwdGtPaFp89aLn",
		sigType: SigTypeECDSA,
		data:    "703532312d646f63756d656e742d646967657374",
		sig: "019c1356656ff259305600d28bd4580aa97e30ea5f45c83bc492f02414d82d07" +
			"183bb9f38f6fb929701b69902e8c79471b531f6e7a6319b35e4f945df62f601d" +
			"29a2015d4c11ffeb93f87aa3a6eb19c583d6dabfeb3709fca7c7901736d9c4d5" +
			"ef530c7d858858eb0afb99c3593601ee7af15eebb5d8a1a84013f47c9a81c1b3" +
			"de73bd20",
	},
	{name: "Ed25519", key: vectorEd25519.publicKey, sigType: SigTypeEDDSA, data: vectorEd25519.hashData, sig: vectorEd25519.signature},
}

// codecX25519 is the x25519-pub multicodec, a key-agreement key this package
// does not support. The supported codecs are defined in keys.go.
const codecX25519 = 0xec

func encodeMultikey(t *testing.T, codec uint64, key []byte) string {
	t.Helper()
	encoded, err := multibase.Encode(multibase.Base58BTC, append(binary.AppendUvarint(nil, codec), key...))
	if err != nil {
		t.Fatalf("multibase.Encode: %v", err)
	}
	return encoded
}

// requireNoVerifier checks that making a verifier failed with an error
// containing want. The verifier must be a nil interface: a nil pointer inside
// a non-nil interface would pass a caller's nil check.
func requireNoVerifier(t *testing.T, verifier SigVerifier, err error, want string) {
	t.Helper()
	requireErrorContains(t, err, want)
	if verifier != nil {
		t.Errorf("verifier = %#v, want a nil interface", verifier)
	}
}

func TestVerifierFromMultikey_KnownSignatures(t *testing.T) {
	for _, vec := range multikeyVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			verifier, data, sig := vec.parse(t)
			if got := verifier.SigType(); got != vec.sigType {
				t.Errorf("sigType = %v, want %v", got, vec.sigType)
			}
			requireSigVerifies(t, verifier, data, sig)
			requireSigRejected(t, verifier, flipBit(data, 0), sig)
			requireSigRejected(t, verifier, data, flipBit(sig, len(sig)-1))
		})
	}
}

func TestVerifier_WrongSignatureLength(t *testing.T) {
	for _, vec := range multikeyVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			verifier, data, sig := vec.parse(t)
			for _, bad := range [][]byte{nil, sig[:len(sig)-1], append(bytes.Clone(sig), 0x00)} {
				ok, err := verifier.Verify(data, bad)
				if ok {
					t.Fatalf("verify accepted a %d-byte signature", len(bad))
				}
				requireErrorContains(t, err, "wrong signature size")
			}
		})
	}
}

func TestEDDSAVerifier_HashIsSHA256(t *testing.T) {
	msg := []byte("canonical-bytes")
	h := crypto.SHA256.New()
	h.Write(msg)
	if got, want := mustVerifier(t, vectorEd25519.publicKey).Hash(msg), h.Sum(nil); !bytes.Equal(got, want) {
		t.Errorf("hash = %x, want SHA-256 %x", got, want)
	}
}

// RFC 8032 rejects a signature whose final byte has its top bit set.
func TestEDDSAVerifier_RejectsNonCanonicalSignature(t *testing.T) {
	verifier := mustVerifier(t, vectorEd25519.publicKey)
	data, sig := mustDecodeHex(t, vectorEd25519.hashData), mustDecodeHex(t, vectorEd25519.signature)
	sig[ed25519.SignatureSize-1] |= 0x80
	requireSigRejected(t, verifier, data, sig)
}

func TestEDDSAVerifier_RejectsOtherKeys(t *testing.T) {
	data, sig := mustDecodeHex(t, vectorEd25519.hashData), mustDecodeHex(t, vectorEd25519.signature)
	otherKey, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x07}, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tests := []struct {
		name string
		key  []byte
	}{
		{name: "different key", key: otherKey},
		// Parsing accepts any 32 bytes. These are not a canonical
		// edwards25519 point, so verification rejects them.
		{name: "off curve", key: bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verifier := mustVerifier(t, encodeMultikey(t, codecEd25519, tt.key))
			requireSigRejected(t, verifier, data, sig)
		})
	}
}

func TestVerifierFromMultikey_UnsupportedCodec(t *testing.T) {
	verifier, err := VerifierFromMultikey(encodeMultikey(t, codecX25519, bytes.Repeat([]byte{0x11}, 32)))
	requireNoVerifier(t, verifier, err, "unsupported multicodec 0xec")
}

func TestVerifierFromMultikey_WrongKeyLength(t *testing.T) {
	tests := []struct {
		name    string
		codec   uint64
		keySize int
	}{
		{name: "P-256", codec: codecP256, keySize: 33},
		{name: "P-384", codec: codecP384, keySize: 49},
		{name: "P-521", codec: codecP521, keySize: 67},
		{name: "Ed25519", codec: codecEd25519, keySize: ed25519.PublicKeySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, size := range []int{tt.keySize - 1, tt.keySize + 1} {
				key := encodeMultikey(t, tt.codec, bytes.Repeat([]byte{0x02}, size))
				verifier, err := VerifierFromMultikey(key)
				requireNoVerifier(t, verifier, err, "public key length")
			}
		})
	}
}

func TestVerifierFromMultikey_InvalidCurvePoint(t *testing.T) {
	tests := []struct {
		name  string
		codec uint64
		size  int
	}{
		{name: "P-256", codec: codecP256, size: 33},
		{name: "P-384", codec: codecP384, size: 49},
		{name: "P-521", codec: codecP521, size: 67},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// x = 7 is inside each curve's field and has no matching y.
			point := make([]byte, tt.size)
			point[0] = 0x02
			point[len(point)-1] = 0x07
			verifier, err := VerifierFromMultikey(encodeMultikey(t, tt.codec, point))
			requireNoVerifier(t, verifier, err, "curve point")
		})
	}
}

// A multicodec prefix that is not a complete, valid varint must fail cleanly.
func TestVerifierFromMultikey_InvalidPrefix(t *testing.T) {
	tests := []struct {
		name    string
		decoded []byte
	}{
		{name: "truncated varint", decoded: []byte{0x80}},
		{name: "varint overflows 64 bits", decoded: bytes.Repeat([]byte{0xff}, binary.MaxVarintLen64+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, err := multibase.Encode(multibase.Base58BTC, tt.decoded)
			if err != nil {
				t.Fatalf("multibase.Encode: %v", err)
			}
			verifier, err := VerifierFromMultikey(key)
			requireNoVerifier(t, verifier, err, "invalid multicodec prefix")
		})
	}
}

func TestVerifierFromMultikey_InvalidEncoding(t *testing.T) {
	verifier, err := VerifierFromMultikey("not-a-multikey")
	requireNoVerifier(t, verifier, err, "decoding multikey")
}

// --- ECDSA signer ---

func TestECDSASigner_SignsWithAllCurves(t *testing.T) {
	msg := []byte("canonical-bytes")
	tests := []struct {
		curve  elliptic.Curve
		hash   crypto.Hash
		sigLen int
	}{
		{curve: elliptic.P256(), hash: crypto.SHA256, sigLen: 64},
		{curve: elliptic.P384(), hash: crypto.SHA384, sigLen: 96},
		{curve: elliptic.P521(), hash: crypto.SHA512, sigLen: 132},
	}
	for _, tt := range tests {
		t.Run(tt.curve.Params().Name, func(t *testing.T) {
			t.Parallel()
			signer, err := GenerateECDSASigner(tt.curve)
			if err != nil {
				t.Fatalf("GenerateECDSASigner: %v", err)
			}
			if got := signer.SigType(); got != SigTypeECDSA {
				t.Errorf("sigType = %v, want %v", got, SigTypeECDSA)
			}

			h := tt.hash.New()
			h.Write(msg)
			if got, want := signer.Hash(msg), h.Sum(nil); !bytes.Equal(got, want) {
				t.Errorf("hash = %x, want %v %x", got, tt.hash, want)
			}

			sig, err := signer.Sign(msg)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if len(sig) != tt.sigLen {
				t.Fatalf("signature length = %d, want %d", len(sig), tt.sigLen)
			}
			requireSigVerifies(t, signer.Verifier(), msg, sig)
			requireSigRejected(t, signer.Verifier(), flipBit(msg, 0), sig)
		})
	}
}

// crypto/ecdsa refuses to sign with a scalar outside 1 to N-1.
func TestECDSASigner_InvalidSigningKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tests := []struct {
		name string
		d    *big.Int
	}{
		{name: "zero", d: big.NewInt(0)},
		{name: "negative", d: big.NewInt(-1)},
		{name: "too large", d: new(big.Int).Lsh(big.NewInt(1), uint(key.Params().N.BitLen()))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := ECDSASigner{signKey: *key}
			signer.signKey.D = tt.d
			sig, err := signer.Sign([]byte("canonical-bytes"))
			requireErrorContains(t, err, "private key scalar")
			if sig != nil {
				t.Errorf("signature = %x, want none", sig)
			}
		})
	}
}

// --- JWK verifiers ---

// jwkVector is a public JWK and a signature over msg made with the matching
// private key. ECDSA signatures are r followed by s, over the curve's paired
// hash of msg. The Ed25519 signature is PureEdDSA over msg.
type jwkVector struct {
	name    string
	jwk     string
	msg     string
	sig     string // hex
	sigType SigType
}

var (
	jwkP256 = jwkVector{
		name: "P-256",
		jwk:  `{"kty":"EC","crv":"P-256","x":"LBNH18YEH_p6qrdchyhAwcMxxILF0JleBHhAXC_q20Y","y":"aE21SsBS2M5tQJj1yDjUWocqcmwMcvBK7MvhAfTHOMk"}`,
		msg:  "jwk test message for P-256",
		sig: "f43dbcaee509e2095b20b25f01682d02ae0f0605dd91d42594468fc9cf34e813" +
			"31460f5e9101bc18fdb6dd7a3394e705b793961783ee73d7889d64e0f8f351e5",
		sigType: SigTypeECDSA,
	}
	jwkP384 = jwkVector{
		name: "P-384",
		jwk:  `{"kty":"EC","crv":"P-384","x":"grf8ZHrRDswRg9J7ZcqLmjR6DsI4FZ6NdwkUQ20wGAyhvFdlFM7VfZ_O0IaGN2uQ","y":"SPNKkIzF7QMW_4e9xRwE_Vl3FE8EhxnYJqQagdsqjBepga-HfE0WBHQ_Dl5jtTev"}`,
		msg:  "jwk test message for P-384",
		sig: "437920ce2bb6da476154e5f9a1b15078635406b2bcee2abf28f3255698a14164" +
			"dea076a3b359550db039476b29afb2cf0817be0c2f9cab8089d45f47f2aecb0d" +
			"565e064e0248f1aeca1073bbc7679c1f3ca6789069a85ba401f80ee324ad2ea7",
		sigType: SigTypeECDSA,
	}
	jwkP521 = jwkVector{
		name: "P-521",
		jwk:  `{"kty":"EC","crv":"P-521","x":"AXV1zjdoQOKEVmjeRducHwsaFP7KwsT8cowwBjdtmo06sfM0psFcFMe7C0SF2mpguVTXYxJoymBzvlv6GnnD8hDK","y":"AD343AwrlJjZ81j4c71ra8vScMHcoq1W9_3REl0vZQmaxvRSj8c7McB-4q1ZIz3RdXJ0qY0MNmJNuK3wT51WpmDL"}`,
		msg:  "jwk test message for P-521",
		sig: "007e8cbfe7c108a808253763082db40625835a6c2b16c0dffdd21ee45792dbd4" +
			"fa23cd8681eb47b41cb61f70dc0a1cd49b2cf7d357648b46e27996ffc6b9f757" +
			"644a00b2d14c658b362d26d6cb1391e2b63c919334cc8fa0b6047602edddbb51" +
			"c3148f269fd447abf0618b43ddcabb42fc4c7fd6e2115f6298c65263c1b542bb" +
			"a4d9c438",
		sigType: SigTypeECDSA,
	}
	jwkEd25519 = jwkVector{
		name: "Ed25519",
		jwk:  `{"kty":"OKP","crv":"Ed25519","x":"ht5vVxVpT5ZAWxOcNw_Odgrd3swyV8yeuph7Nr2d_tI"}`,
		msg:  "jwk test message for Ed25519",
		sig: "e55cc9083bfb10632b7d22892b9f35b64d9e7e0832f95ec0a2285976f45c705d" +
			"be525bbc0db99cda112c298b90c6cf046fdb9955e9b9589b12317dcf698c0e0f",
		sigType: SigTypeEDDSA,
	}
)

// rsaJWK is a 2048-bit RSA public key, a key type this package does not support.
const rsaJWK = `{"kty":"RSA","n":"uteGojBE7QA0wW5aS6ALw-7q8EawPWOW-DHBVrmxaDvXuX4sLn2Gj-2ctRIV7paDnQnv4s-6aLMLiibjW8SbOg4555PCkFxvII5Vftw1EwDoliOEFX-kg0MVRlYgS1bSdPIx1-_WneiNUQC8GQf7Rqdud_e340VZU9r3Gaqt5VhQ9rlGUZQr5eOKNDCAD8PnuKQeDd7FzNaAb0_mdRqAzoK_gJfc1ntZAcxQsZ1dd0As8wrD1YdzuPnl_VEp0RcpHZErGS2_CfwAtAQjxk3ZPHzaWVXv8vFAdHKhV4kOEviRWCk2lucebr4I47RPQXmlJJzME7FhY1qPWO3gEyoosQ","e":"AQAB"}`

func mustParseJWK(t *testing.T, raw string) jwk.Key {
	t.Helper()
	key, err := jwk.ParseKey([]byte(raw))
	if err != nil {
		t.Fatalf("jwk.ParseKey: %v", err)
	}
	return key
}

func TestVerifierFromJWK_KnownSignatures(t *testing.T) {
	for _, vec := range []jwkVector{jwkP256, jwkP384, jwkP521, jwkEd25519} {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			verifier, err := VerifierFromJWK(mustParseJWK(t, vec.jwk))
			if err != nil {
				t.Fatalf("VerifierFromJWK: %v", err)
			}
			if got := verifier.SigType(); got != vec.sigType {
				t.Errorf("sigType = %v, want %v", got, vec.sigType)
			}
			if v, ok := verifier.(*ECDSAVerifier); ok {
				if got := v.pubKey.Curve.Params().Name; got != vec.name {
					t.Errorf("curve = %s, want %s", got, vec.name)
				}
			}

			msg, sig := []byte(vec.msg), mustDecodeHex(t, vec.sig)
			requireSigVerifies(t, verifier, msg, sig)
			requireSigRejected(t, verifier, append(bytes.Clone(msg), '!'), sig)
			requireSigRejected(t, verifier, msg, flipBit(sig, len(sig)-1))
		})
	}
}

func TestVerifierFromJWK_RSAUnsupported(t *testing.T) {
	verifier, err := VerifierFromJWK(mustParseJWK(t, rsaJWK))
	requireNoVerifier(t, verifier, err, "unsupported key type RSA")
}

// --- GetAssertionVerifier ---

// assertionTestDIDDoc has one verification method for each case
// GetAssertionVerifier must handle. Placeholders in braces are replaced with
// keys from the test vectors, so a returned verifier can be checked against a
// known signature.
//   - key-1: P-256 JWK, referenced from assertionMethod by its absolute URL.
//   - key-2: Ed25519 JWK, listed only under authentication.
//   - key-3: Ed25519 Multikey, referenced from assertionMethod.
//   - key-4: malformed JWK, referenced from assertionMethod.
//   - key-5: Ed25519 JWK embedded directly in assertionMethod.
//   - key-6: P-256 Multikey, referenced by the relative URL "#key-6".
//   - key-7: only publicKeyBase58, which is not supported.
//   - key-8: publicKeyMultibase that is not valid base58.
//   - key-9: RSA JWK, a key type this package does not support.
const assertionTestDIDDoc = `{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:example.com:user:101",
  "verificationMethod": [
    {
      "id": "did:web:example.com:user:101#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com:user:101",
      "publicKeyJwk": {P256_JWK}
    },
    {
      "id": "did:web:example.com:user:101#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com:user:101",
      "publicKeyJwk": {ED25519_JWK}
    },
    {
      "id": "did:web:example.com:user:101#key-3",
      "type": "Multikey",
      "controller": "did:web:example.com:user:101",
      "publicKeyMultibase": "{ED25519_MULTIKEY}"
    },
    {
      "id": "did:web:example.com:user:101#key-4",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com:user:101",
      "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "not base64!"}
    },
    {
      "id": "did:web:example.com:user:101#key-6",
      "type": "Multikey",
      "controller": "did:web:example.com:user:101",
      "publicKeyMultibase": "{P256_MULTIKEY}"
    },
    {
      "id": "did:web:example.com:user:101#key-7",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:web:example.com:user:101",
      "publicKeyBase58": "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
    },
    {
      "id": "did:web:example.com:user:101#key-8",
      "type": "Multikey",
      "controller": "did:web:example.com:user:101",
      "publicKeyMultibase": "z0OIl"
    },
    {
      "id": "did:web:example.com:user:101#key-9",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com:user:101",
      "publicKeyJwk": {RSA_JWK}
    }
  ],
  "authentication": ["did:web:example.com:user:101#key-2"],
  "assertionMethod": [
    "did:web:example.com:user:101#key-1",
    "did:web:example.com:user:101#key-3",
    "did:web:example.com:user:101#key-4",
    {
      "id": "did:web:example.com:user:101#key-5",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com:user:101",
      "publicKeyJwk": {ED25519_JWK}
    },
    "#key-6",
    "did:web:example.com:user:101#key-7",
    "did:web:example.com:user:101#key-8",
    "did:web:example.com:user:101#key-9"
  ]
}`

func parseAssertionTestDIDDoc(t *testing.T) *did.Document {
	t.Helper()
	raw := strings.NewReplacer(
		"{P256_JWK}", jwkP256.jwk,
		"{ED25519_JWK}", jwkEd25519.jwk,
		"{P256_MULTIKEY}", vectorP256.publicKey,
		"{ED25519_MULTIKEY}", vectorEd25519.publicKey,
		"{RSA_JWK}", rsaJWK,
	).Replace(assertionTestDIDDoc)
	doc, err := did.ParseDocument(raw)
	if err != nil {
		t.Fatalf("did.ParseDocument: %v", err)
	}
	return doc
}

func requireAssertionVerifierError(t *testing.T, doc *did.Document, keyURL *did.DIDURL, want string) {
	t.Helper()
	verifier, err := GetAssertionVerifier(doc, keyURL)
	requireNoVerifier(t, verifier, err, want)
}

func TestGetAssertionVerifier(t *testing.T) {
	doc := parseAssertionTestDIDDoc(t)
	tests := []struct {
		name     string
		url      string
		wantType SigType
		data     []byte
		sig      []byte
	}{
		{
			name:     "JWK reference",
			url:      "did:web:example.com:user:101#key-1",
			wantType: SigTypeECDSA,
			data:     []byte(jwkP256.msg),
			sig:      mustDecodeHex(t, jwkP256.sig),
		},
		{
			name:     "embedded JWK",
			url:      "did:web:example.com:user:101#key-5",
			wantType: SigTypeEDDSA,
			data:     []byte(jwkEd25519.msg),
			sig:      mustDecodeHex(t, jwkEd25519.sig),
		},
		{
			name:     "Multikey reference",
			url:      "did:web:example.com:user:101#key-3",
			wantType: SigTypeEDDSA,
			data:     mustDecodeHex(t, vectorEd25519.hashData),
			sig:      mustDecodeHex(t, vectorEd25519.signature),
		},
		{
			name:     "relative Multikey reference",
			url:      "did:web:example.com:user:101#key-6",
			wantType: SigTypeECDSA,
			data:     mustDecodeHex(t, vectorP256.hashData),
			sig:      mustDecodeHex(t, vectorP256.signature),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keyURL := did.MustParseDIDURL(tt.url)
			verifier, err := GetAssertionVerifier(doc, &keyURL)
			if err != nil {
				t.Fatalf("GetAssertionVerifier: %v", err)
			}
			if got := verifier.SigType(); got != tt.wantType {
				t.Errorf("sigType = %v, want %v", got, tt.wantType)
			}
			requireSigVerifies(t, verifier, tt.data, tt.sig)
		})
	}
}

func TestGetAssertionVerifier_Rejects(t *testing.T) {
	doc := parseAssertionTestDIDDoc(t)
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "authentication only", url: "did:web:example.com:user:101#key-2", want: "not found or not an assertion method"},
		{name: "unknown fragment", url: "did:web:example.com:user:101#key-99", want: "not found or not an assertion method"},
		{name: "other DID", url: "did:web:other.example:user:101#key-1", want: "not found or not an assertion method"},
		{name: "no fragment", url: "did:web:example.com:user:101", want: "not found or not an assertion method"},
		{name: "malformed JWK", url: "did:web:example.com:user:101#key-4", want: "getting JWK for key did:web:example.com:user:101#key-4"},
		{name: "unsupported key format", url: "did:web:example.com:user:101#key-7", want: "has no publicKeyJwk or publicKeyMultibase"},
		{name: "malformed Multikey", url: "did:web:example.com:user:101#key-8", want: "making verifier for key did:web:example.com:user:101#key-8"},
		{name: "unsupported JWK type", url: "did:web:example.com:user:101#key-9", want: "unsupported key type RSA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keyURL := did.MustParseDIDURL(tt.url)
			requireAssertionVerifierError(t, doc, &keyURL, tt.want)
		})
	}
}

// Errors from go-did and from the key parsers must be wrapped, not replaced.
func TestGetAssertionVerifier_WrapsKeyErrors(t *testing.T) {
	doc := parseAssertionTestDIDDoc(t)
	tests := []struct {
		name    string
		url     string
		wantErr func(*did.VerificationMethod) error
	}{
		{
			name: "JWK",
			url:  "did:web:example.com:user:101#key-4",
			wantErr: func(vm *did.VerificationMethod) error {
				_, err := vm.JWK()
				return err
			},
		},
		{
			name: "Multikey",
			url:  "did:web:example.com:user:101#key-8",
			wantErr: func(vm *did.VerificationMethod) error {
				_, err := VerifierFromMultikey(vm.PublicKeyMultibase)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			keyURL := did.MustParseDIDURL(tt.url)
			wantErr := tt.wantErr(doc.AssertionMethod.FindByID(keyURL))
			if wantErr == nil {
				t.Fatalf("test setup: %s parsed without error", tt.url)
			}
			requireAssertionVerifierError(t, doc, &keyURL, wantErr.Error())
		})
	}
}

// go-did refuses to parse a verification method with two key formats, but a
// document built in code can still hold one.
func TestGetAssertionVerifier_RejectsTwoKeyFormats(t *testing.T) {
	keyURL := did.MustParseDIDURL("did:web:example.com:user:101#key-1")
	var jwkMap map[string]any
	mustUnmarshal(t, []byte(jwkP256.jwk), &jwkMap)
	doc := &did.Document{ID: did.MustParseDID("did:web:example.com:user:101")}
	doc.AddAssertionMethod(&did.VerificationMethod{
		ID:                 keyURL,
		Type:               "JsonWebKey2020",
		Controller:         doc.ID,
		PublicKeyJwk:       jwkMap,
		PublicKeyMultibase: vectorP256.publicKey,
	})
	requireAssertionVerifierError(t, doc, &keyURL, "has both publicKeyJwk and publicKeyMultibase")
}

func TestGetAssertionVerifier_NilInputs(t *testing.T) {
	doc := parseAssertionTestDIDDoc(t)
	keyURL := did.MustParseDIDURL("did:web:example.com:user:101#key-1")

	// A document built in code, rather than parsed, can hold an assertion
	// method entry with no verification method.
	withNilEntry := &did.Document{
		ID:              doc.ID,
		AssertionMethod: did.VerificationRelationships{{}},
	}

	tests := []struct {
		name string
		doc  *did.Document
		url  *did.DIDURL
		want string
	}{
		{name: "nil document", url: &keyURL, want: "no DID document"},
		{name: "nil key URL", doc: doc, want: "no key URL"},
		{name: "both nil", want: "no DID document"},
		{name: "empty document", doc: &did.Document{}, url: &keyURL, want: "not found or not an assertion method"},
		{name: "nil entry", doc: withNilEntry, url: &keyURL, want: "not found or not an assertion method"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requireAssertionVerifierError(t, tt.doc, tt.url, tt.want)
		})
	}
}

// testdata/did1.json is a DID document as a did:web server would publish it.
func TestGetAssertionVerifier_FromFile(t *testing.T) {
	raw, err := os.ReadFile("testdata/did1.json")
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	var doc did.Document
	mustUnmarshal(t, raw, &doc)

	keyURL := did.MustParseDIDURL("did:web:example.org:blah#key-1")
	verifier, err := GetAssertionVerifier(&doc, &keyURL)
	if err != nil {
		t.Fatalf("GetAssertionVerifier: %v", err)
	}
	if got := verifier.SigType(); got != SigTypeECDSA {
		t.Errorf("sigType = %v, want %v", got, SigTypeECDSA)
	}
}

// --- SigType ---

func TestSigType_String(t *testing.T) {
	tests := []struct {
		sigType SigType
		want    string
	}{
		{SigTypeECDSA, "ECDSA"},
		{SigTypeEDDSA, "EdDSA"},
		{SigType(99), "unknown signature type"},
	}
	for _, tt := range tests {
		if got := tt.sigType.String(); got != tt.want {
			t.Errorf("SigType(%d).String() = %q, want %q", int(tt.sigType), got, tt.want)
		}
	}
}
