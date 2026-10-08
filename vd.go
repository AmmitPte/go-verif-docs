package verifdocs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/nuts-foundation/go-did/did"
)

// JSON-LD contexts that define the Data Integrity terms a proof uses. Sign
// adds DataIntegrityContext to a document's @context unless it already
// includes one of these. CredentialsV2Context, the base context of a
// Verifiable Credential, includes the Data Integrity terms.
const (
	DataIntegrityContext = "https://w3id.org/security/data-integrity/v2"
	CredentialsV2Context = "https://www.w3.org/ns/credentials/v2"
)

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

// ProofOptions are the choices a signer makes for a new proof. A zero Created
// or Expires leaves that field out of the proof.
type ProofOptions struct {
	CryptoSuite        CryptoSuiteType
	VerificationMethod *did.DIDURL
	Created            time.Time
	Expires            time.Time
}

// NewProofOptions returns options for a proof made with cs by the key that vm
// names, created now. Nothing checks that vm names the key that will sign;
// that is up to the caller.
func NewProofOptions(cs CryptoSuiteType, vm *did.DIDURL) ProofOptions {
	return ProofOptions{
		CryptoSuite:        cs,
		VerificationMethod: vm,
		// UTC with whole seconds, the plainest form of an XML Schema dateTimeStamp.
		Created: time.Now().UTC().Truncate(time.Second),
	}
}

// Proof is a Data Integrity proof, as found in a SignedDoc.
//
// As the JCS cryptosuites require, a proof's Context is a copy of the
// document's @context, so that the context is signed. A document without an
// @context, such as plain JSON, has a proof without one.
type Proof struct {
	Context            json.RawMessage `json:"@context,omitempty"`
	ProofType          string          `json:"type"`
	ProofPurpose       string          `json:"proofPurpose"`
	CryptoSuite        CryptoSuiteType `json:"cryptosuite"`
	VerificationMethod *did.DIDURL     `json:"verificationMethod"`
	ProofValue         MultibaseBytes  `json:"proofValue,omitempty"`
	Created            time.Time       `json:"created,omitzero"`
	Expires            time.Time       `json:"expires,omitzero"`
}

// SignedDoc is a JSON document secured with a Data Integrity proof. Make one
// with ParseDoc or Sign.
//
// Verify checks Body and RawProofOptions as they are, never a re-encoding,
// so fields that this package or the caller's types do not model are still
// covered by the signature. To change a document, decode Body, edit it,
// and sign it again; changing the fields of a SignedDoc gives one that does
// not verify, or whose Proof does not describe what was signed.
//
// The zero value is an empty document that does not verify.
type SignedDoc struct {
	// Raw is the document with its proof, exactly as parsed or signed. Send
	// these bytes, rather than a re-encoding of a decoded body, so that the
	// document still verifies.
	Raw []byte
	// Body is the document without its proof, as JSON. See DecodeBody.
	Body []byte
	// RawProofOptions is the proof without its proofValue, as JSON. It
	// includes proof fields that Proof does not model.
	RawProofOptions []byte
	// Proof is the proof, parsed.
	Proof Proof
}

// ParseDoc parses a JSON document secured with a Data Integrity proof. It
// checks that the document and its proof are well formed, but not the
// signature or the proof's validity period. Use Verify for those.
//
// The proof must be a DataIntegrityProof for assertionMethod. If it has an
// @context, it must be exactly the document's @context. The JCS cryptosuites
// allow a document to add contexts after the proof's, but that only arises
// with sets of proofs, which this package does not support.
//
// ParseDoc does not check that the @context is one the caller expects.
//
// The returned doc's Raw is data itself, not a copy.
func ParseDoc(data []byte) (SignedDoc, error) {
	// encoding/json silently keeps the last of two duplicate keys, while other
	// parsers may keep the first. JCS rejects duplicates at any depth, so a
	// verified doc cannot be read two different ways.
	if _, err := jcs.Transform(data); err != nil {
		return SignedDoc{}, fmt.Errorf("parsing document: %w", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return SignedDoc{}, fmt.Errorf("parsing document: %w", err)
	}
	rawProof, ok := document["proof"]
	if !ok {
		return SignedDoc{}, errors.New("document has no proof")
	}
	delete(document, "proof")

	var proof Proof
	if err := json.Unmarshal(rawProof, &proof); err != nil {
		return SignedDoc{}, fmt.Errorf("parsing proof: %w", err)
	}
	if err := checkProofConfig(proof); err != nil {
		return SignedDoc{}, err
	}
	if len(proof.ProofValue) == 0 {
		return SignedDoc{}, errors.New("proof has no proofValue")
	}

	// The proof options are every proof field except proofValue, including
	// fields that Proof does not model.
	var proofOptions map[string]json.RawMessage
	if err := json.Unmarshal(rawProof, &proofOptions); err != nil {
		return SignedDoc{}, fmt.Errorf("parsing proof: %w", err)
	}
	delete(proofOptions, "proofValue")

	// A proof without an @context is allowed even when the document has one.
	// The document's @context is then covered by the body hash.
	if proofContext, ok := proofOptions["@context"]; ok && !sameJSON(document["@context"], proofContext) {
		return SignedDoc{}, errors.New("document @context does not match proof @context")
	}

	body, err := json.Marshal(document)
	if err != nil {
		return SignedDoc{}, fmt.Errorf("encoding document: %w", err)
	}
	options, err := json.Marshal(proofOptions)
	if err != nil {
		return SignedDoc{}, fmt.Errorf("encoding proof options: %w", err)
	}
	return SignedDoc{Raw: data, Body: body, RawProofOptions: options, Proof: proof}, nil
}

// DecodeBody decodes Body into v, as json.Unmarshal does. Fields that v does
// not model are left out of v but are still covered by Verify, so re-encoding
// v does not give back the signed document.
func (d SignedDoc) DecodeBody(v any) error {
	return json.Unmarshal(d.Body, v)
}

// MarshalJSON returns Raw, so a SignedDoc can be a field of another JSON
// value. The zero SignedDoc marshals as null.
func (d SignedDoc) MarshalJSON() ([]byte, error) {
	if d.Raw == nil {
		return []byte("null"), nil
	}
	return d.Raw, nil
}

// UnmarshalJSON parses data with ParseDoc. As is the convention, null leaves d
// unchanged.
func (d *SignedDoc) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	// encoding/json may reuse data after this returns.
	parsed, err := ParseDoc(bytes.Clone(data))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
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

// hashData returns the data that cs signs for a body and proof options, using
// hash as the suite's hash function. Only the JCS suites are supported.
func hashData(cs CryptoSuiteType, body, proofOptions []byte, hash func([]byte) []byte) ([]byte, error) {
	switch cs {
	case CryptoSuiteECDSAJCS2019, CryptoSuiteEDDSAJCS2022:
		return jcsHashData(body, proofOptions, hash)
	default:
		return nil, fmt.Errorf("unsupported cryptosuite %s", cs)
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
func (d SignedDoc) Verify(verifier SigVerifier) error {
	return d.VerifyAt(verifier, time.Now())
}

// VerifyAt checks the doc's proof as of the time at. It returns nil only if
// the signature is valid and at falls within the proof's created and expires
// times. The signature is checked first, so the times are only trusted once
// they are known to be signed.
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
func (d SignedDoc) VerifyAt(verifier SigVerifier, at time.Time) error {
	if verifier == nil {
		return errors.New("no verifier given")
	}
	if d.Body == nil {
		return errors.New("empty document")
	}
	if !d.Proof.CryptoSuite.MatchesSigType(verifier.SigType()) {
		return fmt.Errorf("verifier type %s does not match cryptosuite %s", verifier.SigType(), d.Proof.CryptoSuite)
	}
	data, err := hashData(d.Proof.CryptoSuite, d.Body, d.RawProofOptions, verifier.Hash)
	if err != nil {
		return fmt.Errorf("hashing document: %w", err)
	}
	ok, err := verifier.Verify(data, d.Proof.ProofValue)
	if err != nil {
		// The signature is malformed, for example the wrong length.
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}
	if !ok {
		return ErrInvalidSignature
	}
	return d.Proof.checkValidAt(at)
}

// Sign encodes body as JSON and signs it with a proof made from opts. body
// must encode to a JSON object that has no proof. To sign JSON that is
// already encoded, pass it as a json.RawMessage; a plain []byte encodes as a
// base64 string.
//
// A body without an @context, such as plain JSON, is signed as it is. A body
// with an @context is JSON-LD: Sign appends DataIntegrityContext to it unless
// it already includes DataIntegrityContext or CredentialsV2Context, and copies
// the result into the proof, as the JCS cryptosuites require.
func Sign(body any, opts ProofOptions, signer Signer) (SignedDoc, error) {
	if signer == nil {
		return SignedDoc{}, errors.New("no signer given")
	}
	if cs := opts.CryptoSuite; !cs.MatchesSigType(signer.SigType()) {
		return SignedDoc{}, fmt.Errorf("signer type %s does not match cryptosuite %s", signer.SigType(), cs)
	}
	proof := Proof{
		ProofType:          proofType,
		ProofPurpose:       proofPurpose,
		CryptoSuite:        opts.CryptoSuite,
		VerificationMethod: opts.VerificationMethod,
		Created:            opts.Created,
		Expires:            opts.Expires,
	}
	// Refuse to sign a proof that ParseDoc would reject.
	if err := checkProofConfig(proof); err != nil {
		return SignedDoc{}, err
	}

	data, err := json.Marshal(body)
	if err != nil {
		return SignedDoc{}, fmt.Errorf("encoding document: %w", err)
	}
	// Re-encoding the map below would silently drop duplicate keys. JCS
	// rejects them, as ParseDoc does, along with anything else it cannot
	// canonicalize.
	if _, err := jcs.Transform(data); err != nil {
		return SignedDoc{}, fmt.Errorf("parsing document: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return SignedDoc{}, fmt.Errorf("parsing document: %w", err)
	}
	// JSON null unmarshals without error and leaves the map nil.
	if document == nil {
		return SignedDoc{}, errors.New("document is null")
	}
	// The old proof would be hashed as part of the body and then replaced,
	// giving a doc that can never verify. Proof sets are not supported.
	if _, ok := document["proof"]; ok {
		return SignedDoc{}, errors.New("document already has a proof")
	}

	// Make sure a JSON-LD document defines the proof's terms, and sign its
	// @context as part of the proof. Plain JSON stays as it is.
	if context, ok := document["@context"]; ok {
		if context, err = withDataIntegrityContext(context); err != nil {
			return SignedDoc{}, fmt.Errorf("parsing document @context: %w", err)
		}
		document["@context"] = context
		proof.Context = context
	}

	// Hash the body and the proof options, then sign.
	unsignedBody, err := json.Marshal(document)
	if err != nil {
		return SignedDoc{}, fmt.Errorf("encoding document: %w", err)
	}
	options, err := json.Marshal(proof)
	if err != nil {
		return SignedDoc{}, fmt.Errorf("encoding proof options: %w", err)
	}
	hashed, err := hashData(proof.CryptoSuite, unsignedBody, options, signer.Hash)
	if err != nil {
		return SignedDoc{}, fmt.Errorf("hashing document: %w", err)
	}
	if proof.ProofValue, err = signer.Sign(hashed); err != nil {
		return SignedDoc{}, fmt.Errorf("signing document: %w", err)
	}

	// Embed the proof in the document.
	if document["proof"], err = json.Marshal(proof); err != nil {
		return SignedDoc{}, fmt.Errorf("encoding proof: %w", err)
	}
	signed, err := json.Marshal(document)
	if err != nil {
		return SignedDoc{}, fmt.Errorf("encoding signed document: %w", err)
	}

	return SignedDoc{Raw: signed, Body: unsignedBody, RawProofOptions: options, Proof: proof}, nil
}

// withDataIntegrityContext returns an @context value that defines the Data
// Integrity terms. A context that already includes DataIntegrityContext or
// CredentialsV2Context is returned unchanged. Otherwise DataIntegrityContext
// is appended, and a single context or null becomes an array. JSON-LD allows
// a context to be a single value or an array.
func withDataIntegrityContext(context json.RawMessage) (json.RawMessage, error) {
	var value any
	if err := json.Unmarshal(context, &value); err != nil {
		return nil, err
	}
	var values []any
	switch v := value.(type) {
	case nil:
	case []any:
		values = v
	default:
		values = []any{v}
	}
	for _, v := range values {
		if v == DataIntegrityContext || v == CredentialsV2Context {
			return context, nil
		}
	}
	return json.Marshal(append(values, DataIntegrityContext))
}

// sameJSON reports whether a and b are the same JSON value, comparing their
// JCS canonical forms. A value that cannot be canonicalized, including a
// missing one, matches nothing.
func sameJSON(a, b json.RawMessage) bool {
	ca, errA := jcs.Transform(a)
	cb, errB := jcs.Transform(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}
