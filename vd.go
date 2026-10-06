package verifdocs

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/nuts-foundation/go-did/did"
)

// Encode the cryptosuite for a verifiable doc as an int,
// makes it easier to handle in Go.
type CryptoSuiteType int

const (
	CryptoSuite_Unknown = iota
	CryptoSuite_ECDSA_JCS_2019
	CryptoSuite_ECDSA_RDFC_2019
	CryptoSuite_EDDSA_JCS_2022
	CryptoSuite_EDDSA_RDFC_2022
	// TODO
)

func (cs CryptoSuiteType) String() string {
	switch cs {
	case CryptoSuite_ECDSA_JCS_2019:
		return "ecdsa-jcs-2019"
	case CryptoSuite_ECDSA_RDFC_2019:
		return "ecdsa-rdfc-2019"
	case CryptoSuite_EDDSA_JCS_2022:
		return "eddsa-jcs-2022"
	case CryptoSuite_EDDSA_RDFC_2022:
		return "eddsa-rdfc-2022"
	}
	return "Unknown crypto suite"
}

func (cs CryptoSuiteType) MarshalText() ([]byte, error) {
	return []byte(cs.String()), nil
}

func ParseCryptoSuite(str string) CryptoSuiteType {
	switch str {
	case "ecdsa-jcs-2019":
		return CryptoSuite_ECDSA_JCS_2019
	case "ecdsa-rdfc-2019":
		return CryptoSuite_ECDSA_RDFC_2019
	case "eddsa-jcs-2022":
		return CryptoSuite_EDDSA_JCS_2022
	case "eddsa-rdfc-2022":
		return CryptoSuite_EDDSA_RDFC_2022
	default:
		return CryptoSuite_Unknown
	}
}

func (cs *CryptoSuiteType) UnmarshalText(text []byte) error {
	parsed := ParseCryptoSuite(string(text))
	if parsed == CryptoSuite_Unknown {
		return fmt.Errorf("Unknown crypto suite: %q", string(text))
	}
	*cs = parsed
	return nil
}

func (cs CryptoSuiteType) MatchesSigType(sigType SigType) bool {
	switch cs {
	case CryptoSuite_ECDSA_JCS_2019, CryptoSuite_ECDSA_RDFC_2019:
		return sigType == SigType_ECDSA
	case CryptoSuite_EDDSA_JCS_2022, CryptoSuite_EDDSA_RDFC_2022:
		return sigType == SigType_EDDSA
	}
	return false
}

// Data integrity proof attached to verifiable docs.
// If the ProofValue is omitted then it's just the config.
// Unmarshals from JSON transparently.
// NB: we don't check for a specific type or purpose here,
// callers must check that this is correct for the app!
type Proof struct {
	ProofType          string          `json:"type"`
	ProofPurpose       string          `json:"proofPurpose"`
	CryptoSuite        CryptoSuiteType `json:"cryptosuite"`
	VerificationMethod *did.DIDURL     `json:"verificationMethod"`
	ProofValue         MultibaseBytes  `json:"proofValue,omitempty"`
	Created            time.Time       `json:"created,omitempty"`
	Expiry             time.Time       `json:"expiry,omitempty"`
}

// A Verifiable Doc is just a body (without the proof), and a proof.
// We keep the raw proof value in order to serialize it when checking
// signatures, in case there are unsupported fields.
type VerifiableDoc struct {
	Body  []byte
	Proof Proof
	// Always contains the proof section without the ProofValue
	rawProofOptions []byte
}

// Unmarshal a byte array in JSON to a VerifiableDoc.
// Parses only the top level JSON to extract the proof,
// checks that the proof is well formed, but doesn't verify the sig.
// Ends with the proof parsed, the body is the top level dictionary
// (with the proof removed), and the raw proof JSON (needed for verifying
// the signature later).
// NB: enforces proof type to be DataIntegrityProof and purpose to be assertionMethod,
// since that should always be the case for a verifiable doc.
func ParseDoc(data []byte) (VerifiableDoc, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return VerifiableDoc{}, fmt.Errorf("Error parsing doc: %w", err)
	}

	// Extract, verify, and remove the proof section
	rawProof, exists := document["proof"]
	if !exists {
		return VerifiableDoc{}, fmt.Errorf("Doc has no proof section")
	}
	var proof Proof
	if err := json.Unmarshal(rawProof, &proof); err != nil {
		return VerifiableDoc{}, fmt.Errorf("Error parsing doc proof: %w", err)
	}
	if proof.ProofType != "DataIntegrityProof" {
		return VerifiableDoc{}, fmt.Errorf("Unsupported proof type: %s", proof.ProofType)
	}
	if proof.ProofPurpose != "assertionMethod" {
		return VerifiableDoc{}, fmt.Errorf("Unsupported proof type: %s", proof.ProofType)
	}
	delete(document, "proof")

	bodyBytes, err := json.Marshal(document)
	if err != nil {
		// Should be impossible, but just in case.
		return VerifiableDoc{}, err
	}

	// Extract the proof in such a way that we can remove the proofValue
	var proofMap map[string]json.RawMessage
	if err := json.Unmarshal(rawProof, &proofMap); err != nil {
		// This should be impossible if we parsed it previously, but just in case.
		return VerifiableDoc{}, fmt.Errorf("Error parsing proof: %w", err)
	}
	delete(proofMap, "proofValue")
	proofBytes, err := json.Marshal(proofMap)
	if err != nil {
		// Should be impossible, but just in case.
		return VerifiableDoc{}, err
	}

	return VerifiableDoc{
		Body:            bodyBytes,
		Proof:           proof,
		rawProofOptions: proofBytes,
	}, nil
}

// Get the hash of the doc appropriate for cryptosuite.
func (vd VerifiableDoc) GetHash(hashfn func([]byte) []byte) ([]byte, error) {
	switch vd.Proof.CryptoSuite {
	case CryptoSuite_ECDSA_JCS_2019, CryptoSuite_EDDSA_JCS_2022:
		// do nothing
	default:
		return []byte{}, fmt.Errorf("Unsupported hashing for cryptosuite %s", vd.Proof.CryptoSuite)
	}
	var dh DocHasher = JCSHasher(hashfn)
	return dh.Hash(vd.Body, vd.rawProofOptions)
}

// Use a function pointer for the canonicalization method (JCS vs RDFC)
// to make it generic for both.
type DocHasher struct {
	canonicalizer func([]byte) ([]byte, error)
	hasher        func([]byte) []byte
}

// NB: Assumes that body has proof removed, and proofConfig has proofValue removed!!
func (dh DocHasher) Hash(body []byte, proofConfig []byte) ([]byte, error) {
	canonicalBody, err := dh.canonicalizer(body)
	if err != nil {
		return []byte{}, err
	}
	bodyHash := dh.hasher(canonicalBody)

	canonicalProof, err := dh.canonicalizer(proofConfig)
	if err != nil {
		return []byte{}, err
	}
	proofHash := dh.hasher(canonicalProof)

	hashData := slices.Concat(proofHash[:], bodyHash[:])
	return hashData, nil
}

func JCSHasher(hashfn func([]byte) []byte) DocHasher {
	return DocHasher{
		canonicalizer: jcs.Transform,
		hasher:        hashfn,
	}
}

// Intentionally leave it to the caller to figure out the key for verification.
func (vd VerifiableDoc) Verify(verifier SigVerifier) (bool, error) {
	if !vd.Proof.CryptoSuite.MatchesSigType(verifier.sigType()) {
		return false, fmt.Errorf("Verifier type %s does not match cryptosuite %s", verifier.sigType(), vd.Proof.CryptoSuite)
	}
	dataHash, err := vd.GetHash(verifier.hash)
	if err != nil {
		return false, fmt.Errorf("Error hashing doc: %w", err)
	}
	return verifier.verify(dataHash, vd.Proof.ProofValue)
}

// NB: we have no way to verify that DID URL given matches signer. Up to caller to ensure that!
func MakeVerifiableDoc(doc any, cs CryptoSuiteType, vm *did.DIDURL) (VerifiableDoc, error) {
	// Make sure we can marshall to bytes.
	bodyBytes, err := json.Marshal(doc)
	if err != nil {
		return VerifiableDoc{}, err
	}

	proof := Proof{
		ProofType:          "DataIntegrityProof",
		ProofPurpose:       "assertionMethod",
		CryptoSuite:        cs,
		VerificationMethod: vm,
		Created:            time.Now(),
	}

	vd := VerifiableDoc{
		Body:  bodyBytes,
		Proof: proof,
	}

	return vd, nil
}

func (vd *VerifiableDoc) Sign(signer Signer) ([]byte, error) {
	// Check that crypto suite and signer are compatible.
	cs := vd.Proof.CryptoSuite
	if !cs.MatchesSigType(signer.sigType()) {
		return []byte{}, fmt.Errorf("Signer type %s does not match cryptosuite %s", signer.sigType(), cs)
	}

	// Make sure we get rid of the proof value to overwrite it.
	vd.Proof.ProofValue = nil

	// Serialize the proof options so we can hash and then sign.
	rawProofOptions, err := json.Marshal(vd.Proof)
	if err != nil {
		// Should be impossible, but just in case.
		return []byte{}, err
	}
	vd.rawProofOptions = rawProofOptions

	dataHash, err := vd.GetHash(signer.hash)
	if err != nil {
		return []byte{}, fmt.Errorf("Error hashing doc: %w", err)
	}

	sig, err := signer.sign(dataHash)
	if err != nil {
		return []byte{}, fmt.Errorf("Error signing doc: %w", err)
	}
	vd.Proof.ProofValue = sig

	// Assemble the doc by embedding the proof inside of it.
	var docMap map[string]json.RawMessage
	if err := json.Unmarshal(vd.Body, &docMap); err != nil {
		return []byte{}, fmt.Errorf("Error parsing base doc: %w", err)
	}
	// JSON null unmarshals without error and leaves the map nil.
	if docMap == nil {
		return []byte{}, fmt.Errorf("Error parsing base doc: document is null")
	}
	rawProof, err := json.Marshal(vd.Proof)
	if err != nil {
		// Should be impossible, but just in case.
		return []byte{}, err
	}
	docMap["proof"] = rawProof

	bytes, err := json.Marshal(docMap)
	if err != nil {
		// Should be impossible, but just in case.
		return []byte{}, err
	}

	return bytes, nil
}
