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
	"errors"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
	"github.com/nuts-foundation/go-did/did"
)

// SigType is the signature algorithm of a key.
type SigType int

const (
	SigTypeECDSA SigType = iota
	SigTypeEDDSA
)

// String returns the algorithm's name.
func (t SigType) String() string {
	switch t {
	case SigTypeECDSA:
		return "ECDSA"
	case SigTypeEDDSA:
		return "EdDSA"
	}
	return "unknown signature type"
}

// SigVerifier checks signatures made with one public key. Use
// GetAssertionVerifier, VerifierFromMultikey or VerifierFromJWK to make one.
type SigVerifier interface {
	// Verify reports whether sig is a valid signature over data.
	Verify(data []byte, sig []byte) (bool, error)
	SigType() SigType
	// Hash is the cryptosuite's hash function for this key.
	Hash(data []byte) []byte
	// ToMultikey returns the public key as a base58btc Multikey, the form
	// used in a verification method's publicKeyMultibase. It returns "" if
	// there is no key, or the key has no Multikey encoding.
	ToMultikey() string
}

// Signer signs with one private key.
type Signer interface {
	// Sign returns a signature over data.
	Sign(data []byte) ([]byte, error)
	SigType() SigType
	// Hash is the cryptosuite's hash function for this key.
	Hash(data []byte) []byte
	Verifier() SigVerifier
}

// fieldBytes returns the size in bytes of a coordinate on curve. P-521 needs
// 66 bytes, so the bit size is rounded up.
func fieldBytes(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// hashForCurve hashes data with the algorithm that FIPS 186-5 pairs with the
// curve: SHA-256 for P-256, SHA-384 for P-384 and SHA-512 for P-521.
func hashForCurve(curve elliptic.Curve, data []byte) []byte {
	switch curve.Params().BitSize {
	case 384:
		sum := sha512.Sum384(data)
		return sum[:]
	case 521:
		sum := sha512.Sum512(data)
		return sum[:]
	default:
		sum := sha256.Sum256(data)
		return sum[:]
	}
}

// ECDSAVerifier verifies ECDSA signatures with a P-256, P-384 or P-521 key.
// Make one with NewECDSAVerifier or ECDSAVerifierFromBytes. The zero value
// has no key and rejects every signature with an error.
type ECDSAVerifier struct {
	pubKey *ecdsa.PublicKey
}

// NewECDSAVerifier returns a verifier for pub. The key must be a valid point
// on a curve that crypto/ecdsa supports.
func NewECDSAVerifier(pub *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	if pub == nil || pub.Curve == nil {
		return nil, errors.New("no ECDSA public key given")
	}
	// Bytes fails for a point that is not on the curve.
	if _, err := pub.Bytes(); err != nil {
		return nil, fmt.Errorf("invalid ECDSA public key: %w", err)
	}
	return &ECDSAVerifier{pubKey: pub}, nil
}

// hasKey reports whether v was made with a key, rather than being the zero
// value.
func (v ECDSAVerifier) hasKey() bool {
	return v.pubKey != nil && v.pubKey.Curve != nil
}

// Verify checks an IEEE P1363 signature: r followed by s, each the size of a
// curve coordinate.
func (v ECDSAVerifier) Verify(data []byte, sig []byte) (bool, error) {
	if !v.hasKey() {
		return false, errors.New("ECDSA verifier has no public key")
	}
	size := fieldBytes(v.pubKey.Curve)
	if len(sig) != 2*size {
		return false, fmt.Errorf("wrong signature size: got %d bytes, want %d", len(sig), 2*size)
	}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	return ecdsa.Verify(v.pubKey, v.Hash(data), r, s), nil
}

// Hash returns nil for the zero value, which has no curve to choose a hash.
func (v ECDSAVerifier) Hash(data []byte) []byte {
	if !v.hasKey() {
		return nil
	}
	return hashForCurve(v.pubKey.Curve, data)
}

func (v ECDSAVerifier) SigType() SigType {
	return SigTypeECDSA
}

// ToMultikey encodes the key as a compressed point after its curve's
// multicodec. It returns "" for the zero value, and for a curve with no
// Multikey codec, such as P-224.
func (v ECDSAVerifier) ToMultikey() string {
	if !v.hasKey() {
		return ""
	}
	name := v.pubKey.Curve.Params().Name
	for codec, curve := range multikeyCurves {
		if curve.Params().Name == name {
			return encodeMultikey(codec, elliptic.MarshalCompressed(curve, v.pubKey.X, v.pubKey.Y))
		}
	}
	return ""
}

// ECDSASigner signs with an ECDSA private key. Make one with NewECDSASigner
// or GenerateECDSASigner. The zero value has no key and fails to sign.
type ECDSASigner struct {
	signKey ecdsa.PrivateKey
}

// NewECDSASigner returns a signer for key. The key must be valid on a curve
// that crypto/ecdsa supports. The signer keeps a copy of key.
func NewECDSASigner(key *ecdsa.PrivateKey) (*ECDSASigner, error) {
	if key == nil || key.Curve == nil {
		return nil, errors.New("no ECDSA private key given")
	}
	// Bytes fails for a scalar out of range or a public point not on the curve.
	if _, err := key.Bytes(); err != nil {
		return nil, fmt.Errorf("invalid ECDSA private key: %w", err)
	}
	return &ECDSASigner{signKey: *key}, nil
}

// GenerateECDSASigner returns a signer with a new random key on curve.
func GenerateECDSASigner(curve elliptic.Curve) (*ECDSASigner, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}
	return &ECDSASigner{signKey: *key}, nil
}

// hasKey reports whether signer was made with a key, rather than being the
// zero value.
func (signer ECDSASigner) hasKey() bool {
	return signer.signKey.Curve != nil
}

// Sign returns an IEEE P1363 signature, r followed by s, as the ECDSA
// cryptosuites require.
func (signer ECDSASigner) Sign(data []byte) ([]byte, error) {
	if !signer.hasKey() {
		return nil, errors.New("ECDSA signer has no private key")
	}
	r, s, err := ecdsa.Sign(rand.Reader, &signer.signKey, signer.Hash(data))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	size := fieldBytes(signer.signKey.Curve)
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return sig, nil
}

// Hash returns nil for the zero value, which has no curve to choose a hash.
func (signer ECDSASigner) Hash(data []byte) []byte {
	if !signer.hasKey() {
		return nil
	}
	return hashForCurve(signer.signKey.Curve, data)
}

func (signer ECDSASigner) SigType() SigType {
	return SigTypeECDSA
}

func (signer ECDSASigner) Verifier() SigVerifier {
	return ECDSAVerifier{pubKey: &signer.signKey.PublicKey}
}

// EDDSAVerifier verifies Ed25519 signatures. Make one with
// EDDSAVerifierFromBytes. The zero value has no key and rejects every
// signature with an error.
type EDDSAVerifier struct {
	pubKey ed25519.PublicKey
}

// Verify checks a PureEdDSA (Ed25519) signature. Ed25519 hashes data itself,
// with SHA-512.
func (v EDDSAVerifier) Verify(data []byte, sig []byte) (bool, error) {
	// ed25519.Verify panics on a key of the wrong length.
	if len(v.pubKey) != ed25519.PublicKeySize {
		return false, errors.New("EdDSA verifier has no public key")
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("wrong signature size: got %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return ed25519.Verify(v.pubKey, data, sig), nil
}

// Hash is SHA-256, the hash the EdDSA cryptosuites apply to the canonical
// proof options and document.
func (v EDDSAVerifier) Hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (v EDDSAVerifier) SigType() SigType {
	return SigTypeEDDSA
}

// ToMultikey encodes the raw key after the ed25519-pub multicodec. It returns
// "" for the zero value.
func (v EDDSAVerifier) ToMultikey() string {
	if len(v.pubKey) != ed25519.PublicKeySize {
		return ""
	}
	return encodeMultikey(codecEd25519, v.pubKey)
}

// Public key multicodecs from the multiformats table. A Multikey is one of
// these codecs as an unsigned varint, followed by the key bytes.
const (
	codecP256    = 0x1200 // p256-pub, compressed point
	codecP384    = 0x1201 // p384-pub, compressed point
	codecP521    = 0x1202 // p521-pub, compressed point
	codecEd25519 = 0xed   // ed25519-pub; encoded as the varint bytes 0xed 0x01
)

// multikeyCurves maps each supported ECDSA multicodec to its curve.
var multikeyCurves = map[uint64]elliptic.Curve{
	codecP256: elliptic.P256(),
	codecP384: elliptic.P384(),
	codecP521: elliptic.P521(),
}

// encodeMultikey returns codec as an unsigned varint followed by key, encoded
// as base58btc multibase.
func encodeMultikey(codec uint64, key []byte) string {
	// Encode fails only for an unknown encoding, and Base58BTC is known.
	encoded, _ := multibase.Encode(multibase.Base58BTC, append(binary.AppendUvarint(nil, codec), key...))
	return encoded
}

// VerifierFromMultikey returns a verifier for a Multikey-encoded public key,
// as found in a verification method's publicKeyMultibase.
func VerifierFromMultikey(multikey string) (SigVerifier, error) {
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("decoding multikey: %w", err)
	}
	codec, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, errors.New("invalid multicodec prefix")
	}
	keyBytes := decoded[n:]

	// Check each constructor's error before returning its result. Returning a
	// nil *ECDSAVerifier or *EDDSAVerifier as a SigVerifier would give a
	// non-nil interface that holds a nil pointer.
	if codec == codecEd25519 {
		v, err := EDDSAVerifierFromBytes(keyBytes)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	curve, ok := multikeyCurves[codec]
	if !ok {
		return nil, fmt.Errorf("unsupported multicodec 0x%x", codec)
	}
	v, err := ECDSAVerifierFromBytes(curve, keyBytes)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// ECDSAVerifierFromBytes returns a verifier for a compressed public key point
// on curve.
func ECDSAVerifierFromBytes(curve elliptic.Curve, keyBytes []byte) (*ECDSAVerifier, error) {
	want := fieldBytes(curve) + 1
	if len(keyBytes) != want {
		return nil, fmt.Errorf("invalid ECDSA public key length: got %d, want %d", len(keyBytes), want)
	}
	x, y := elliptic.UnmarshalCompressed(curve, keyBytes)
	if x == nil {
		return nil, fmt.Errorf("invalid %s curve point", curve.Params().Name)
	}
	return &ECDSAVerifier{pubKey: &ecdsa.PublicKey{Curve: curve, X: x, Y: y}}, nil
}

// EDDSAVerifierFromBytes returns a verifier for a raw 32-byte Ed25519 public key.
func EDDSAVerifierFromBytes(keyBytes []byte) (*EDDSAVerifier, error) {
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid EdDSA public key length: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}
	return &EDDSAVerifier{pubKey: bytes.Clone(keyBytes)}, nil
}

// VerifierFromJWK returns a verifier for an EC or Ed25519 public JWK.
func VerifierFromJWK(key jwk.Key) (SigVerifier, error) {
	var raw any
	if err := jwk.Export(key, &raw); err != nil {
		return nil, fmt.Errorf("exporting JWK: %w", err)
	}
	// As in VerifierFromMultikey, check each constructor's error so a nil
	// pointer is never returned inside a non-nil SigVerifier.
	switch pub := raw.(type) {
	case *ecdsa.PublicKey:
		v, err := NewECDSAVerifier(pub)
		if err != nil {
			return nil, err
		}
		return v, nil
	case ed25519.PublicKey:
		v, err := EDDSAVerifierFromBytes(pub)
		if err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported key type %s", key.KeyType())
	}
}

// GetAssertionVerifier returns a verifier for the key that keyURL names in a
// DID document. The key must be listed under assertionMethod, because that is
// the relationship a DID controller uses to authorise keys for signing
// documents. It can be a reference to a verification method or embedded directly.
//
// The key can be given as publicKeyJwk or as a Multikey in publicKeyMultibase.
// Other formats, such as publicKeyBase58, are not supported.
func GetAssertionVerifier(doc *did.Document, keyURL *did.DIDURL) (SigVerifier, error) {
	if doc == nil {
		return nil, errors.New("no DID document given")
	}
	if keyURL == nil {
		return nil, errors.New("no key URL given")
	}

	// go-did resolves references, including relative ones, when it parses the
	// document, so this finds both referenced and embedded assertion methods.
	vm := doc.AssertionMethod.FindByID(*keyURL)
	if vm == nil {
		return nil, fmt.Errorf("key %s not found or not an assertion method", keyURL)
	}
	return verifierFromMethod(vm)
}

// verifierFromMethod makes a verifier from the key material in a verification
// method. A method must not carry the same key in more than one format, so
// one with both publicKeyJwk and publicKeyMultibase is rejected.
func verifierFromMethod(vm *did.VerificationMethod) (SigVerifier, error) {
	hasJWK := vm.PublicKeyJwk != nil
	hasMultibase := vm.PublicKeyMultibase != ""

	switch {
	case hasJWK && hasMultibase:
		return nil, fmt.Errorf("key %s has both publicKeyJwk and publicKeyMultibase", vm.ID)
	case hasJWK:
		key, err := vm.JWK()
		if err != nil {
			return nil, fmt.Errorf("getting JWK for key %s: %w", vm.ID, err)
		}
		// go-did returns a nil key only when there is no publicKeyJwk, which
		// was checked above. Guard anyway rather than pass a nil key on.
		if key == nil {
			return nil, fmt.Errorf("key %s has no publicKeyJwk", vm.ID)
		}
		verifier, err := VerifierFromJWK(key)
		if err != nil {
			return nil, fmt.Errorf("making verifier for key %s: %w", vm.ID, err)
		}
		return verifier, nil
	case hasMultibase:
		verifier, err := VerifierFromMultikey(vm.PublicKeyMultibase)
		if err != nil {
			return nil, fmt.Errorf("making verifier for key %s: %w", vm.ID, err)
		}
		return verifier, nil
	default:
		return nil, fmt.Errorf("key %s has no publicKeyJwk or publicKeyMultibase", vm.ID)
	}
}
