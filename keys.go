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

type SigType int

const (
	SigType_ECDSA = iota
	SigType_EDDSA
)

func (cs SigType) String() string {
	switch cs {
	case SigType_ECDSA:
		return "SigType_ECDSA"
	case SigType_EDDSA:
		return "SigType_EDDSA"
	}
	return "Unknown verifier type"
}

// Generic interface for something that wraps up the verification key.
type SigVerifier interface {
	verify(dataHash []byte, sig []byte) (bool, error)
	sigType() SigType
	hash(data []byte) []byte
}

type ECDSAVerifier struct {
	pubKey *ecdsa.PublicKey
}

func (v ECDSAVerifier) verify(data []byte, sig []byte) (bool, error) {
	// Field size in bytes. P-521 is 66 bytes, so integer division of BitSize is not enough.
	keySize := (v.pubKey.Params().BitSize + 7) / 8
	if len(sig) != keySize*2 {
		return false, fmt.Errorf("wrong signature size, got %d bytes exp %d", len(sig), keySize*2)
	}
	digest := v.hash(data)
	// TODO: there has to be a better way to do this!
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	return ecdsa.Verify(v.pubKey, digest, r, s), nil
}

// Hash the document digest with the algorithm paired to the curve by FIPS 186-5:
// SHA-256 for P-256, SHA-384 for P-384, and SHA-512 for P-521.
func hashForECDSABitSize(bitSize int, data []byte) []byte {
	switch bitSize {
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

func (v ECDSAVerifier) hash(data []byte) []byte {
	return hashForECDSABitSize(v.pubKey.Curve.Params().BitSize, data)
}

func (v ECDSAVerifier) sigType() SigType {
	return SigType_ECDSA
}

// Generic interface for something that wraps up a signing key
type Signer interface {
	sign(dataHash []byte) ([]byte, error)
	sigType() SigType
	hash(data []byte) []byte
	verifier() SigVerifier
}

type ECDSASigner struct {
	signKey ecdsa.PrivateKey
}

func GenerateECDSASigner(curve elliptic.Curve) (*ECDSASigner, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Error generating ECDSA key: %w", err)
	}
	return &ECDSASigner{signKey: *priv}, nil
}

func (s ECDSASigner) hash(data []byte) []byte {
	return hashForECDSABitSize(s.signKey.Curve.Params().BitSize, data)
}

func (s ECDSASigner) sigType() SigType {
	return SigType_ECDSA
}

func (signer ECDSASigner) sign(data []byte) ([]byte, error) {
	digest := signer.hash(data)
	r, s, err := ecdsa.Sign(rand.Reader, &signer.signKey, digest)
	if err != nil {
		return []byte{}, fmt.Errorf("Error signing: %w", err)
	}
	keySize := (signer.signKey.Params().BitSize + 7) / 8
	bytes := make([]byte, 2*keySize)
	r.FillBytes(bytes[:keySize])
	s.FillBytes(bytes[keySize:])
	return bytes, nil
}

func (s ECDSASigner) verifier() SigVerifier {
	return ECDSAVerifier{pubKey: &s.signKey.PublicKey}
}

type EDDSAVerifier struct {
	pubKey ed25519.PublicKey
}

// verify checks a PureEdDSA (Ed25519) signature over data.
// data is the concatenation of the SHA-256 proof hash and the SHA-256
// document hash. Ed25519 applies SHA-512 to that byte string itself.
func (v EDDSAVerifier) verify(data []byte, sig []byte) (bool, error) {
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("wrong signature size, got %d bytes exp %d", len(sig), ed25519.SignatureSize)
	}
	return ed25519.Verify(v.pubKey, data, sig), nil
}

// hash is SHA-256, the cryptosuite hash for eddsa-jcs-2022 and eddsa-rdfc-2022.
// It covers the canonical proof and the canonical document before concatenation.
func (v EDDSAVerifier) hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (v EDDSAVerifier) sigType() SigType {
	return SigType_EDDSA
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

// VerifierFromMultikey returns a verifier for a Multikey-encoded public key,
// as found in a verification method's publicKeyMultibase.
func VerifierFromMultikey(data string) (SigVerifier, error) {
	_, decoded, err := multibase.Decode(data)
	if err != nil {
		return nil, err
	}
	codec, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, errors.New("invalid multicodec prefix")
	}
	keyBytes := decoded[n:]

	if codec == codecEd25519 {
		v, err := EDDSAVerifierFromBytes(keyBytes)
		if err != nil {
			return nil, err
		}
		return v, nil
	}
	curve, ok := multikeyCurves[codec]
	if !ok {
		return nil, fmt.Errorf("unsupported multicodec: 0x%x", codec)
	}
	v, err := ECDSAVerifierFromBytes(curve, keyBytes)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func ECDSAVerifierFromBytes(curve elliptic.Curve, keyBytes []byte) (*ECDSAVerifier, error) {
	expBytes := (curve.Params().BitSize+7)/8 + 1
	if len(keyBytes) != expBytes {
		return nil, fmt.Errorf("Invalid ECDSA public key length, got %d expected %d", len(keyBytes), expBytes)
	}

	x, y := elliptic.UnmarshalCompressed(curve, keyBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid %s curve point", curve.Params().Name)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return &ECDSAVerifier{pubKey: pubKey}, nil
}

func EDDSAVerifierFromBytes(keyBytes []byte) (*EDDSAVerifier, error) {
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Invalid EdDSA public key length, got %d expected %d", len(keyBytes), ed25519.PublicKeySize)
	}
	return &EDDSAVerifier{pubKey: bytes.Clone(keyBytes)}, nil
}

func VerifierFromJWK(key jwk.Key) (SigVerifier, error) {
	var rawKey interface{}
	if err := jwk.Export(key, &rawKey); err != nil {
		return nil, err
	}

	switch pub := rawKey.(type) {
	case *ecdsa.PublicKey:
		return &ECDSAVerifier{pubKey: pub}, nil
	case ed25519.PublicKey:
		return &EDDSAVerifier{pubKey: pub}, nil
	default:
		return nil, fmt.Errorf("Unsupported key type: %s", key.KeyType().String())
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
		return nil, fmt.Errorf("No DID document given")
	}
	if keyURL == nil {
		return nil, fmt.Errorf("No key URL given")
	}

	// go-did resolves references, including relative ones, when it parses the
	// document, so this finds both referenced and embedded assertion methods.
	vm := doc.AssertionMethod.FindByID(*keyURL)
	if vm == nil {
		return nil, fmt.Errorf("Key %s not found or not an assertion method", keyURL)
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
		return nil, fmt.Errorf("Key %s has both publicKeyJwk and publicKeyMultibase", vm.ID)
	case hasJWK:
		key, err := vm.JWK()
		if err != nil {
			return nil, fmt.Errorf("Could not get JWK for key %s: %w", vm.ID, err)
		}
		// go-did returns a nil key only when there is no publicKeyJwk, which
		// was checked above. Guard anyway rather than pass a nil key on.
		if key == nil {
			return nil, fmt.Errorf("Key %s has no publicKeyJwk", vm.ID)
		}
		verifier, err := VerifierFromJWK(key)
		if err != nil {
			return nil, fmt.Errorf("Could not make verifier for key %s: %w", vm.ID, err)
		}
		return verifier, nil
	case hasMultibase:
		verifier, err := VerifierFromMultikey(vm.PublicKeyMultibase)
		if err != nil {
			return nil, fmt.Errorf("Could not make verifier for key %s: %w", vm.ID, err)
		}
		return verifier, nil
	default:
		return nil, fmt.Errorf("Key %s has no publicKeyJwk or publicKeyMultibase", vm.ID)
	}
}
