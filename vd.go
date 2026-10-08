package verifdocs

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/nuts-foundation/go-did/did"
)

// DataIntegrityContext is the JSON-LD context that defines Data Integrity
// proofs. Sign adds it to the @context of every document it signs.
const DataIntegrityContext = "https://w3id.org/security/data-integrity/v2"

// The only proof type and purpose this package signs or accepts.
const (
	proofType    = "DataIntegrityProof"
	proofPurpose = "assertionMethod"
)

// Errors returned by Verify and VerifyAt when a well-formed proof does not
// verify. Use errors.Is to check for them.
var (
	// ErrInvalidSignature means the proof's signature is not valid for the
	// document and key.
	ErrInvalidSignature = errors.New("invalid signature")
	// ErrProofNotYetValid and ErrProofExpired mean the verification time is
	// outside the proof's validity period.
	ErrProofNotYetValid = errors.New("proof is not yet valid")
	ErrProofExpired     = errors.New("proof has expired")
)

// CryptoSuiteType identifies a Data Integrity cryptosuite. It marshals to and
// from the suite's name, such as "ecdsa-jcs-2019".
type CryptoSuiteType int

const (
	CryptoSuiteUnknown CryptoSuiteType = iota
	CryptoSuiteECDSAJCS2019
	CryptoSuiteECDSARDFC2019
	CryptoSuiteEDDSAJCS2022
	CryptoSuiteEDDSARDFC2022
)

// String returns the suite's name, or "unknown crypto suite" for a value that
// is not a known suite.
func (cs CryptoSuiteType) String() string {
	name, err := cs.MarshalText()
	if err != nil {
		return "unknown crypto suite"
	}
	return string(name)
}

// MarshalText returns the suite's name. CryptoSuiteType is an int, so it can
// hold values other than the declared constants. CryptoSuiteUnknown and any
// such value are an error, so a proof never carries a name that UnmarshalText
// would reject.
func (cs CryptoSuiteType) MarshalText() ([]byte, error) {
	switch cs {
	case CryptoSuiteECDSAJCS2019:
		return []byte("ecdsa-jcs-2019"), nil
	case CryptoSuiteECDSARDFC2019:
		return []byte("ecdsa-rdfc-2019"), nil
	case CryptoSuiteEDDSAJCS2022:
		return []byte("eddsa-jcs-2022"), nil
	case CryptoSuiteEDDSARDFC2022:
		return []byte("eddsa-rdfc-2022"), nil
	}
	return nil, fmt.Errorf("cannot marshal unknown crypto suite %d", int(cs))
}

// ParseCryptoSuite returns the suite with the given name, or
// CryptoSuiteUnknown if the name is not recognised.
func ParseCryptoSuite(name string) CryptoSuiteType {
	for cs := CryptoSuiteECDSAJCS2019; cs <= CryptoSuiteEDDSARDFC2022; cs++ {
		if cs.String() == name {
			return cs
		}
	}
	return CryptoSuiteUnknown
}

// UnmarshalText parses a suite name. An unrecognised name is an error.
func (cs *CryptoSuiteType) UnmarshalText(text []byte) error {
	parsed := ParseCryptoSuite(string(text))
	if parsed == CryptoSuiteUnknown {
		return fmt.Errorf("unknown crypto suite %q", text)
	}
	*cs = parsed
	return nil
}

// MatchesSigType reports whether the suite uses the given signature type.
// An unknown suite matches none.
func (cs CryptoSuiteType) MatchesSigType(sigType SigType) bool {
	switch cs {
	case CryptoSuiteECDSAJCS2019, CryptoSuiteECDSARDFC2019:
		return sigType == SigTypeECDSA
	case CryptoSuiteEDDSAJCS2022, CryptoSuiteEDDSARDFC2022:
		return sigType == SigTypeEDDSA
	}
	return false
}

// Proof is a Data Integrity proof. Without a ProofValue it is the proof
// configuration that Sign completes. A proof never has its own @context; the
// document's @context applies to it.
type Proof struct {
	ProofType          string          `json:"type"`
	ProofPurpose       string          `json:"proofPurpose"`
	CryptoSuite        CryptoSuiteType `json:"cryptosuite"`
	VerificationMethod *did.DIDURL     `json:"verificationMethod"`
	ProofValue         MultibaseBytes  `json:"proofValue,omitempty"`
	Created            time.Time       `json:"created,omitzero"`
	Expires            time.Time       `json:"expires,omitzero"`
}

// VerifiableDoc is a document body and the Data Integrity proof over it.
type VerifiableDoc struct {
	// Body is the document as JSON, without its proof.
	Body  []byte
	Proof Proof
	// rawProofOptions is the proof as JSON, without its proofValue. It is
	// hashed as is, so proof fields this package does not model are still
	// covered by the signature.
	rawProofOptions []byte
}

// ParseDoc parses a JSON document secured with a Data Integrity proof. It
// checks that the document and its proof are well formed, but not the
// signature or the proof's validity period. Use Verify for those.
//
// The proof must be a DataIntegrityProof for assertionMethod, and must not
// have its own @context.
func ParseDoc(data []byte) (VerifiableDoc, error) {
	// encoding/json silently keeps the last of two duplicate keys, while other
	// parsers may keep the first. JCS rejects duplicates at any depth, so a
	// verified doc cannot be read two different ways.
	if _, err := jcs.Transform(data); err != nil {
		return VerifiableDoc{}, fmt.Errorf("parsing document: %w", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return VerifiableDoc{}, fmt.Errorf("parsing document: %w", err)
	}
	rawProof, ok := document["proof"]
	if !ok {
		return VerifiableDoc{}, errors.New("document has no proof")
	}
	delete(document, "proof")

	var proof Proof
	if err := json.Unmarshal(rawProof, &proof); err != nil {
		return VerifiableDoc{}, fmt.Errorf("parsing proof: %w", err)
	}
	if err := checkProofConfig(proof); err != nil {
		return VerifiableDoc{}, err
	}
	if len(proof.ProofValue) == 0 {
		return VerifiableDoc{}, errors.New("proof has no proofValue")
	}

	// The proof options are every proof field except proofValue, including
	// fields that Proof does not model.
	var proofOptions map[string]json.RawMessage
	if err := json.Unmarshal(rawProof, &proofOptions); err != nil {
		return VerifiableDoc{}, fmt.Errorf("parsing proof: %w", err)
	}
	if _, ok := proofOptions["@context"]; ok {
		return VerifiableDoc{}, errors.New("proof must not have an @context")
	}
	delete(proofOptions, "proofValue")

	body, err := json.Marshal(document)
	if err != nil {
		return VerifiableDoc{}, fmt.Errorf("encoding document: %w", err)
	}
	options, err := json.Marshal(proofOptions)
	if err != nil {
		return VerifiableDoc{}, fmt.Errorf("encoding proof options: %w", err)
	}
	return VerifiableDoc{Body: body, Proof: proof, rawProofOptions: options}, nil
}

// checkProofConfig checks the proof fields that every proof must have before
// it is signed or after it is parsed. It does not look at the proof value.
// The cryptosuite can only be unknown here when the field is missing, because
// unmarshalling rejects any suite name it does not recognise.
func checkProofConfig(p Proof) error {
	if p.ProofType != proofType {
		return fmt.Errorf("unsupported proof type %q", p.ProofType)
	}
	if p.ProofPurpose != proofPurpose {
		return fmt.Errorf("unsupported proof purpose %q", p.ProofPurpose)
	}
	if p.CryptoSuite == CryptoSuiteUnknown {
		return errors.New("proof has no cryptosuite")
	}
	if p.VerificationMethod == nil {
		return errors.New("proof has no verificationMethod")
	}
	if !p.Created.IsZero() && !p.Expires.IsZero() && !p.Expires.After(p.Created) {
		return errors.New("proof expires at or before it was created")
	}
	return nil
}

// checkValidAt checks that at falls within the proof's validity period. The
// proof is valid from created, inclusive, until expires, exclusive. A missing
// created or expires sets no bound.
func (p Proof) checkValidAt(at time.Time) error {
	if !p.Created.IsZero() && at.Before(p.Created) {
		return fmt.Errorf("%w: created %s, checked at %s",
			ErrProofNotYetValid, p.Created.Format(time.RFC3339), at.Format(time.RFC3339))
	}
	if !p.Expires.IsZero() && !at.Before(p.Expires) {
		return fmt.Errorf("%w: expired %s, checked at %s",
			ErrProofExpired, p.Expires.Format(time.RFC3339), at.Format(time.RFC3339))
	}
	return nil
}

// hashData returns the data that the doc's cryptosuite signs, using hash as
// the suite's hash function. Only the JCS suites are supported.
func (vd VerifiableDoc) hashData(hash func([]byte) []byte) ([]byte, error) {
	switch vd.Proof.CryptoSuite {
	case CryptoSuiteECDSAJCS2019, CryptoSuiteEDDSAJCS2022:
		return jcsHashData(vd.Body, vd.rawProofOptions, hash)
	default:
		return nil, fmt.Errorf("unsupported cryptosuite %s", vd.Proof.CryptoSuite)
	}
}

// jcsHashData canonicalizes the proof options and the body with JCS
// (RFC 8785), hashes each, and returns the proof options hash followed by the
// body hash. body must not contain the proof, and proofOptions must not
// contain the proofValue.
func jcsHashData(body, proofOptions []byte, hash func([]byte) []byte) ([]byte, error) {
	canonicalOptions, err := jcs.Transform(proofOptions)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing proof options: %w", err)
	}
	canonicalBody, err := jcs.Transform(body)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing document: %w", err)
	}
	return slices.Concat(hash(canonicalOptions), hash(canonicalBody)), nil
}

// Verify checks the doc's proof as of the current time. See VerifyAt.
func (vd VerifiableDoc) Verify(verifier SigVerifier) error {
	return vd.VerifyAt(verifier, time.Now())
}

// VerifyAt checks the doc's proof as of the time at. It returns nil only if
// the signature is valid and at falls within the proof's created and expires
// times.
//
// A signature that does not verify returns an error wrapping
// ErrInvalidSignature. A proof that is not valid at that time returns an
// error wrapping ErrProofNotYetValid or ErrProofExpired. Any other error
// means the proof could not be checked, for example because the verifier's
// key type does not match the cryptosuite.
//
// The caller is responsible for choosing the verifier, normally with
// GetAssertionVerifier, and for checking that the key belongs to the
// expected signer.
func (vd VerifiableDoc) VerifyAt(verifier SigVerifier, at time.Time) error {
	if verifier == nil {
		return errors.New("no verifier given")
	}
	if !vd.Proof.CryptoSuite.MatchesSigType(verifier.sigType()) {
		return fmt.Errorf("verifier type %s does not match cryptosuite %s", verifier.sigType(), vd.Proof.CryptoSuite)
	}
	if err := vd.Proof.checkValidAt(at); err != nil {
		return err
	}
	data, err := vd.hashData(verifier.hash)
	if err != nil {
		return fmt.Errorf("hashing document: %w", err)
	}
	ok, err := verifier.verify(data, vd.Proof.ProofValue)
	if err != nil {
		// The signature is malformed, for example the wrong length.
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	if !ok {
		return ErrInvalidSignature
	}
	return nil
}

// MakeVerifiableDoc encodes doc as JSON and prepares an assertionMethod proof
// for it, created now, ready for Sign. Nothing checks that vm names the key
// that will sign it; that is up to the caller.
func MakeVerifiableDoc(doc any, cs CryptoSuiteType, vm *did.DIDURL) (VerifiableDoc, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return VerifiableDoc{}, err
	}
	return VerifiableDoc{
		Body: body,
		Proof: Proof{
			ProofType:          proofType,
			ProofPurpose:       proofPurpose,
			CryptoSuite:        cs,
			VerificationMethod: vm,
			// UTC with whole seconds, the plainest form of an XML Schema dateTimeStamp.
			Created: time.Now().UTC().Truncate(time.Second),
		},
	}, nil
}

// Sign signs the doc and returns it as JSON with the proof embedded. It first
// adds DataIntegrityContext to the document's @context, so Body changes too.
// On success vd holds the new proof value and can be verified directly.
// A doc that is already signed cannot be signed again.
func (vd *VerifiableDoc) Sign(signer Signer) ([]byte, error) {
	// Re-encoding the map below would silently drop duplicate keys. JCS
	// rejects them, as ParseDoc does, along with anything else it cannot
	// canonicalize.
	if _, err := jcs.Transform(vd.Body); err != nil {
		return nil, fmt.Errorf("parsing document: %w", err)
	}
	if cs := vd.Proof.CryptoSuite; !cs.MatchesSigType(signer.sigType()) {
		return nil, fmt.Errorf("signer type %s does not match cryptosuite %s", signer.sigType(), cs)
	}
	// Refuse to sign a proof that ParseDoc would reject.
	if err := checkProofConfig(vd.Proof); err != nil {
		return nil, err
	}
	if len(vd.Proof.ProofValue) > 0 {
		return nil, errors.New("document is already signed")
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(vd.Body, &document); err != nil {
		return nil, fmt.Errorf("parsing document: %w", err)
	}
	// JSON null unmarshals without error and leaves the map nil.
	if document == nil {
		return nil, errors.New("document is null")
	}
	// The old proof would be hashed as part of the body and then replaced,
	// giving a doc that can never verify. Proof sets are not supported.
	if _, ok := document["proof"]; ok {
		return nil, errors.New("document already has a proof")
	}

	// Add the Data Integrity context, so the proof's terms are defined.
	context, err := withDataIntegrityContext(document["@context"])
	if err != nil {
		return nil, fmt.Errorf("parsing document @context: %w", err)
	}
	document["@context"] = context
	if vd.Body, err = json.Marshal(document); err != nil {
		return nil, fmt.Errorf("encoding document: %w", err)
	}

	// Hash the body and the proof options, then sign.
	if vd.rawProofOptions, err = json.Marshal(vd.Proof); err != nil {
		return nil, fmt.Errorf("encoding proof options: %w", err)
	}
	data, err := vd.hashData(signer.hash)
	if err != nil {
		return nil, fmt.Errorf("hashing document: %w", err)
	}
	if vd.Proof.ProofValue, err = signer.sign(data); err != nil {
		return nil, fmt.Errorf("signing document: %w", err)
	}

	// Assemble the signed doc by embedding the proof in it.
	if document["proof"], err = json.Marshal(vd.Proof); err != nil {
		return nil, fmt.Errorf("encoding proof: %w", err)
	}
	signed, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encoding signed document: %w", err)
	}
	return signed, nil
}

// withDataIntegrityContext returns an @context value that includes
// DataIntegrityContext. A context that already includes it is returned
// unchanged. Otherwise it is appended, and a missing or null context becomes
// an array of just that context. JSON-LD allows a context to be a single
// value or an array.
func withDataIntegrityContext(context json.RawMessage) (json.RawMessage, error) {
	var values []any
	if len(context) > 0 {
		var value any
		if err := json.Unmarshal(context, &value); err != nil {
			return nil, err
		}
		switch v := value.(type) {
		case nil:
		case []any:
			values = v
		default:
			values = []any{v}
		}
	}
	for _, v := range values {
		if s, ok := v.(string); ok && s == DataIntegrityContext {
			return context, nil
		}
	}
	return json.Marshal(append(values, DataIntegrityContext))
}
