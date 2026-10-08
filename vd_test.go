package verifdocs

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"math/big"
	"regexp"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
)

// --- Helpers ---

const testKeyURL = "did:web:example.com:user:101#key-1"

func sampleDoc() map[string]any {
	return map[string]any{"id": 101, "name": "Alice"}
}

func mustMakeVerifiableDoc(t *testing.T, doc any, cs CryptoSuiteType) VerifiableDoc {
	t.Helper()
	vm := did.MustParseDIDURL(testKeyURL)
	vd, err := MakeVerifiableDoc(doc, cs, &vm)
	if err != nil {
		t.Fatalf("MakeVerifiableDoc: %v", err)
	}
	return vd
}

func mustECDSASigner(t *testing.T) *ECDSASigner {
	t.Helper()
	signer, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("GenerateECDSASigner: %v", err)
	}
	return signer
}

func mustSign(t *testing.T, vd *VerifiableDoc, signer Signer) []byte {
	t.Helper()
	signed, err := vd.Sign(signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

func mustParseDoc(t *testing.T, data []byte) VerifiableDoc {
	t.Helper()
	vd, err := ParseDoc(data)
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	return vd
}

// signedTestDoc signs doc with the given proof times, then parses the result
// as a verifier would receive it. It also returns a verifier for the key.
func signedTestDoc(t *testing.T, doc any, created, expires time.Time) (VerifiableDoc, SigVerifier) {
	t.Helper()
	signer := mustECDSASigner(t)
	vd := mustMakeVerifiableDoc(t, doc, CryptoSuiteECDSAJCS2019)
	vd.Proof.Created = created
	vd.Proof.Expires = expires
	return mustParseDoc(t, mustSign(t, &vd, signer)), signer.verifier()
}

func requireParseDocError(t *testing.T, doc string, want string) {
	t.Helper()
	_, err := ParseDoc([]byte(doc))
	requireErrorContains(t, err, want)
}

func requireSignError(t *testing.T, vd *VerifiableDoc, signer Signer, want string) {
	t.Helper()
	signed, err := vd.Sign(signer)
	requireErrorContains(t, err, want)
	if signed != nil {
		t.Errorf("Sign returned %s with an error", signed)
	}
}

// validProofFields returns the fields of a proof that ParseDoc accepts.
// The proof value is a placeholder and will not verify.
func validProofFields() map[string]any {
	return map[string]any{
		"type":               "DataIntegrityProof",
		"proofPurpose":       "assertionMethod",
		"cryptosuite":        "ecdsa-jcs-2019",
		"verificationMethod": testKeyURL,
		"proofValue":         exampleProofValueEncoded,
	}
}

// docWithProof returns a small document with the given proof fields.
func docWithProof(t *testing.T, proof map[string]any) string {
	t.Helper()
	return string(mustMarshal(t, map[string]any{"id": "urn:example:1", "proof": proof}))
}

// signedFields splits a signed document into its top-level fields and its
// proof's fields, as raw JSON.
func signedFields(t *testing.T, signed []byte) (document, proof map[string]json.RawMessage) {
	t.Helper()
	mustUnmarshal(t, signed, &document)
	mustUnmarshal(t, document["proof"], &proof)
	return document, proof
}

// requireRawField checks a raw JSON field. An empty want means the field must be absent.
func requireRawField(t *testing.T, fields map[string]json.RawMessage, name, want string) {
	t.Helper()
	got, ok := fields[name]
	switch {
	case want == "" && ok:
		t.Errorf("%s = %s, want it absent", name, got)
	case want != "" && !ok:
		t.Errorf("%s is absent, want %s", name, want)
	case want != "" && string(got) != want:
		t.Errorf("%s = %s, want %s", name, got, want)
	}
}

// stubSigner stands in for signature types this package cannot generate,
// and for a sign call that fails on its own.
type stubSigner struct {
	kind    SigType
	signErr error
}

func (s stubSigner) sign([]byte) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	return []byte{0x01}, nil
}

func (s stubSigner) sigType() SigType        { return s.kind }
func (s stubSigner) hash(data []byte) []byte { return data }
func (s stubSigner) verifier() SigVerifier   { return nil }

// refuseJSON is a document whose MarshalJSON method fails.
type refuseJSON struct{}

func (refuseJSON) MarshalJSON() ([]byte, error) { return nil, errors.New("refuse to marshal") }

// --- CryptoSuiteType ---

func TestCryptoSuiteType_Names(t *testing.T) {
	tests := []struct {
		suite CryptoSuiteType
		name  string
	}{
		{CryptoSuiteECDSAJCS2019, "ecdsa-jcs-2019"},
		{CryptoSuiteECDSARDFC2019, "ecdsa-rdfc-2019"},
		{CryptoSuiteEDDSAJCS2022, "eddsa-jcs-2022"},
		{CryptoSuiteEDDSARDFC2022, "eddsa-rdfc-2022"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.suite.String(); got != tt.name {
				t.Errorf("String() = %q, want %q", got, tt.name)
			}
			if got := ParseCryptoSuite(tt.name); got != tt.suite {
				t.Errorf("ParseCryptoSuite(%q) = %v, want %v", tt.name, got, tt.suite)
			}
			var parsed CryptoSuiteType
			if err := parsed.UnmarshalText([]byte(tt.name)); err != nil {
				t.Fatalf("UnmarshalText: %v", err)
			}
			if parsed != tt.suite {
				t.Errorf("UnmarshalText(%q) = %v, want %v", tt.name, parsed, tt.suite)
			}
		})
	}
}

func TestCryptoSuiteType_UnknownName(t *testing.T) {
	const name = "not-a-suite"
	if got := ParseCryptoSuite(name); got != CryptoSuiteUnknown {
		t.Errorf("ParseCryptoSuite(%q) = %v, want %v", name, got, CryptoSuiteUnknown)
	}
	suite := CryptoSuiteECDSAJCS2019
	requireErrorContains(t, suite.UnmarshalText([]byte(name)), name)
	if suite != CryptoSuiteECDSAJCS2019 {
		t.Errorf("suite = %v after a failed UnmarshalText, want it unchanged", suite)
	}
}

// Marshalling an unknown suite must fail, rather than write a name that
// unmarshalling would then reject. CryptoSuiteType is an int, so any value
// outside the declared constants is unknown too.
func TestCryptoSuiteType_MarshalUnknown(t *testing.T) {
	tests := []struct {
		name  string
		suite CryptoSuiteType
	}{
		{name: "unknown constant", suite: CryptoSuiteUnknown},
		{name: "past the last constant", suite: CryptoSuiteEDDSARDFC2022 + 1},
		{name: "negative", suite: CryptoSuiteType(-1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if text, err := tt.suite.MarshalText(); err == nil {
				t.Errorf("MarshalText = %q, want an error", text)
			}
			if out, err := json.Marshal(Proof{CryptoSuite: tt.suite}); err == nil {
				t.Errorf("json.Marshal = %s, want an error", out)
			}
			if got := tt.suite.String(); got != "unknown crypto suite" {
				t.Errorf("String() = %q, want %q", got, "unknown crypto suite")
			}
			if tt.suite.MatchesSigType(SigTypeECDSA) || tt.suite.MatchesSigType(SigTypeEDDSA) {
				t.Error("unknown suite matches a signature type")
			}
		})
	}
}

// --- W3C vectors ---

func TestW3CVectors_HashData(t *testing.T) {
	for _, vec := range w3cVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			got, err := vectorDoc(t, vec).hashData(mustVerifier(t, vec.publicKey).hash)
			if err != nil {
				t.Fatalf("hashData: %v", err)
			}
			if hex.EncodeToString(got) != vec.hashData {
				t.Errorf("hashData = %x, want %s", got, vec.hashData)
			}
		})
	}
}

func TestW3CVectors_Verify(t *testing.T) {
	for _, vec := range w3cVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			vd := vectorDoc(t, vec)
			if got := hex.EncodeToString(vd.Proof.ProofValue); got != vec.signature {
				t.Errorf("proofValue = %s, want %s", got, vec.signature)
			}
			requireNoError(t, vd.Verify(mustVerifier(t, vec.publicKey)))
		})
	}
}

func TestW3CVectors_RejectTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *VerifiableDoc)
	}{
		{
			name: "body",
			mutate: func(t *testing.T, vd *VerifiableDoc) {
				vd.Body = replaceOnce(t, vd.Body, `"Alumni Credential"`, `"Tampered"`)
			},
		},
		{
			name: "proof options",
			mutate: func(t *testing.T, vd *VerifiableDoc) {
				vd.rawProofOptions = replaceOnce(t, vd.rawProofOptions, "2023-02-24", "2023-02-25")
			},
		},
		{
			name: "signature",
			mutate: func(_ *testing.T, vd *VerifiableDoc) {
				vd.Proof.ProofValue = flipBit(vd.Proof.ProofValue, 0)
			},
		},
		{
			name: "signature length",
			mutate: func(_ *testing.T, vd *VerifiableDoc) {
				vd.Proof.ProofValue = vd.Proof.ProofValue[:len(vd.Proof.ProofValue)-1]
			},
		},
	}
	for _, vec := range w3cVectors {
		for _, tt := range tests {
			t.Run(vec.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				vd := vectorDoc(t, vec)
				tt.mutate(t, &vd)
				requireErrorIs(t, vd.Verify(mustVerifier(t, vec.publicKey)), ErrInvalidSignature)
			})
		}
	}
}

// replaceOnce replaces the first old in b with new, failing the test if b
// does not contain old.
func replaceOnce(t *testing.T, b []byte, old, new string) []byte {
	t.Helper()
	if !bytes.Contains(b, []byte(old)) {
		t.Fatalf("test setup: %s does not contain %s", b, old)
	}
	return bytes.Replace(b, []byte(old), []byte(new), 1)
}

// The W3C vectors carry an @context in their proofs, as the JCS cryptosuite
// specifications require. This package does not accept that.
func TestW3CVectors_ParseDocRejectsProofContext(t *testing.T) {
	for _, vec := range w3cVectors {
		t.Run(vec.name, func(t *testing.T) {
			t.Parallel()
			requireParseDocError(t, vec.signed(), "proof must not have an @context")
		})
	}
}

// --- ParseDoc ---

// rdfcExampleDoc uses eddsa-rdfc-2022, which ParseDoc accepts but this
// package cannot hash. Its proof has a field, "habla", that Proof does not model.
const rdfcExampleDoc = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/data-integrity/v2"
  ],
  "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321",
  "type": "Person",
  "name": "Alice",
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2026-03-28T15:40:00Z",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321#z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321",
    "proofPurpose": "assertionMethod",
    "proofValue": "z1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "habla": "blah"
  }
}`

func TestParseDoc(t *testing.T) {
	vd := mustParseDoc(t, []byte(rdfcExampleDoc))

	p := vd.Proof
	if p.ProofType != "DataIntegrityProof" || p.ProofPurpose != "assertionMethod" {
		t.Errorf("type, purpose = %q, %q", p.ProofType, p.ProofPurpose)
	}
	if p.CryptoSuite != CryptoSuiteEDDSARDFC2022 {
		t.Errorf("cryptosuite = %v, want %v", p.CryptoSuite, CryptoSuiteEDDSARDFC2022)
	}
	const wantVM = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321#z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321"
	if got := p.VerificationMethod.String(); got != wantVM {
		t.Errorf("verificationMethod = %s, want %s", got, wantVM)
	}
	if !bytes.Equal(p.ProofValue, exampleProofValue) {
		t.Errorf("proofValue = %x, want %x", p.ProofValue, exampleProofValue)
	}
	if want := time.Date(2026, 3, 28, 15, 40, 0, 0, time.UTC); !p.Created.Equal(want) {
		t.Errorf("created = %s, want %s", p.Created, want)
	}

	var body map[string]json.RawMessage
	mustUnmarshal(t, vd.Body, &body)
	requireRawField(t, body, "proof", "")
	requireRawField(t, body, "name", `"Alice"`)

	// The proof options keep fields that Proof does not model, so they are
	// still covered by the signature.
	var options map[string]json.RawMessage
	mustUnmarshal(t, vd.rawProofOptions, &options)
	requireRawField(t, options, "habla", `"blah"`)
	requireRawField(t, options, "proofValue", "")
}

// ParseDoc only decodes the top-level object, so other fields are kept as
// they are, even a string that looks like broken JSON.
func TestParseDoc_KeepsOtherFieldsRaw(t *testing.T) {
	doc := mustMarshal(t, map[string]any{
		"id":                "urn:example:1",
		"credentialSubject": "{not: valid}",
		"proof":             validProofFields(),
	})
	var body map[string]json.RawMessage
	mustUnmarshal(t, mustParseDoc(t, doc).Body, &body)
	requireRawField(t, body, "credentialSubject", `"{not: valid}"`)
}

func TestParseDoc_RejectsMalformed(t *testing.T) {
	proof := string(mustMarshal(t, validProofFields()))
	withProofField := func(name, value string) string {
		fields := validProofFields()
		fields[name] = value
		return docWithProof(t, fields)
	}
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{name: "not JSON", doc: `{"id":`, want: "parsing document"},
		{name: "not an object", doc: `[1, 2, 3]`, want: "parsing document"},
		{name: "no proof", doc: `{"id":"urn:example:1"}`, want: "document has no proof"},
		{name: "proof is an array", doc: `{"id":"urn:example:1","proof":[1, 2, 3]}`, want: "parsing proof"},
		{name: "unknown cryptosuite", doc: withProofField("cryptosuite", "nope"), want: "parsing proof"},
		{name: "bad created", doc: withProofField("created", "yesterday"), want: "parsing proof"},
		{name: "bad proofValue", doc: withProofField("proofValue", "not-valid"), want: "parsing proof"},
		// encoding/json keeps the last of two duplicate keys, while other
		// parsers may keep the first, so duplicates are rejected.
		{name: "duplicate top-level key", doc: `{"name":"Alice","name":"Mallory","proof":` + proof + `}`, want: "Duplicate key"},
		{name: "two proofs", doc: `{"name":"Alice","proof":` + proof + `,"proof":` + proof + `}`, want: "Duplicate key"},
		{name: "duplicate key in proof", doc: `{"name":"Alice","proof":{"type":"Other",` + proof[1:] + `}`, want: "Duplicate key"},
		{name: "duplicate nested key", doc: `{"subject":{"name":"Alice","name":"Mallory"},"proof":` + proof + `}`, want: "Duplicate key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requireParseDocError(t, tt.doc, tt.want)
		})
	}
}

// The @context belongs on the document only, so any @context on the proof
// is rejected, even an empty or null one.
func TestParseDoc_RejectsProofContext(t *testing.T) {
	tests := []struct {
		name    string
		context any
	}{
		{name: "array", context: []any{"https://www.w3.org/ns/credentials/v2"}},
		{name: "string", context: DataIntegrityContext},
		{name: "empty array", context: []any{}},
		{name: "null", context: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields := validProofFields()
			fields["@context"] = tt.context
			requireParseDocError(t, docWithProof(t, fields), "proof must not have an @context")
		})
	}
}

// ParseDoc requires every field that a Data Integrity proof must carry.
// A value that is present but empty or null counts as missing.
func TestParseDoc_MissingProofFields(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value any // used instead of removing the field when not nil
		want  string
	}{
		{name: "no type", field: "type", want: `unsupported proof type ""`},
		{name: "empty type", field: "type", value: "", want: `unsupported proof type ""`},
		{name: "no purpose", field: "proofPurpose", want: `unsupported proof purpose ""`},
		{name: "empty purpose", field: "proofPurpose", value: "", want: `unsupported proof purpose ""`},
		{name: "no cryptosuite", field: "cryptosuite", want: "proof has no cryptosuite"},
		{name: "no verification method", field: "verificationMethod", want: "proof has no verificationMethod"},
		{name: "null verification method", field: "verificationMethod", value: json.RawMessage("null"), want: "proof has no verificationMethod"},
		{name: "no proof value", field: "proofValue", want: "proof has no proofValue"},
		{name: "null proof value", field: "proofValue", value: json.RawMessage("null"), want: "proof has no proofValue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields := validProofFields()
			delete(fields, tt.field)
			if tt.value != nil {
				fields[tt.field] = tt.value
			}
			requireParseDocError(t, docWithProof(t, fields), tt.want)
		})
	}
}

func TestParseDoc_WrongTypeOrPurpose(t *testing.T) {
	tests := []struct {
		field string
		value string
		want  string
	}{
		{field: "type", value: "Ed25519Signature2020", want: `unsupported proof type "Ed25519Signature2020"`},
		{field: "proofPurpose", value: "authentication", want: `unsupported proof purpose "authentication"`},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			t.Parallel()
			fields := validProofFields()
			fields[tt.field] = tt.value
			requireParseDocError(t, docWithProof(t, fields), tt.want)
		})
	}
}

func TestParseDoc_ProofTimestamps(t *testing.T) {
	tests := []struct {
		name        string
		times       map[string]any
		wantCreated time.Time
		wantExpires time.Time
	}{
		{
			name:        "created and expires",
			times:       map[string]any{"created": "2026-03-28T15:40:00Z", "expires": "2027-03-28T15:40:00Z"},
			wantCreated: time.Date(2026, 3, 28, 15, 40, 0, 0, time.UTC),
			wantExpires: time.Date(2027, 3, 28, 15, 40, 0, 0, time.UTC),
		},
		{
			name:        "offset and fractional seconds",
			times:       map[string]any{"created": "2026-10-06T15:06:41.070247+08:00"},
			wantCreated: time.Date(2026, 10, 6, 7, 6, 41, 70247000, time.UTC),
		},
		{name: "absent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fields := validProofFields()
			maps.Copy(fields, tt.times)
			p := mustParseDoc(t, []byte(docWithProof(t, fields))).Proof
			if !p.Created.Equal(tt.wantCreated) {
				t.Errorf("created = %s, want %s", p.Created, tt.wantCreated)
			}
			if !p.Expires.Equal(tt.wantExpires) {
				t.Errorf("expires = %s, want %s", p.Expires, tt.wantExpires)
			}
		})
	}
}

// A proof that expires at or before it was created can never be valid.
func TestParseDoc_ExpiresNotAfterCreated(t *testing.T) {
	for _, expires := range []string{"2026-03-28T15:40:00Z", "2026-03-28T15:39:59Z"} {
		t.Run(expires, func(t *testing.T) {
			t.Parallel()
			fields := validProofFields()
			fields["created"] = "2026-03-28T15:40:00Z"
			fields["expires"] = expires
			requireParseDocError(t, docWithProof(t, fields), "proof expires at or before it was created")
		})
	}
}

// --- MakeVerifiableDoc ---

func TestMakeVerifiableDoc(t *testing.T) {
	before := time.Now().Truncate(time.Second)
	vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
	after := time.Now()

	p := vd.Proof
	if p.ProofType != "DataIntegrityProof" || p.ProofPurpose != "assertionMethod" {
		t.Errorf("type, purpose = %q, %q", p.ProofType, p.ProofPurpose)
	}
	if p.CryptoSuite != CryptoSuiteECDSAJCS2019 {
		t.Errorf("cryptosuite = %v, want %v", p.CryptoSuite, CryptoSuiteECDSAJCS2019)
	}
	if got := p.VerificationMethod.String(); got != testKeyURL {
		t.Errorf("verificationMethod = %s, want %s", got, testKeyURL)
	}
	if got, want := string(vd.Body), `{"id":101,"name":"Alice"}`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}

	// created is now, in UTC, with whole seconds.
	if p.Created.Location() != time.UTC || p.Created.Nanosecond() != 0 {
		t.Errorf("created = %s, want UTC with whole seconds", p.Created.Format(time.RFC3339Nano))
	}
	if p.Created.Before(before) || p.Created.After(after) {
		t.Errorf("created = %s, want between %s and %s", p.Created, before, after)
	}
	if !p.Expires.IsZero() {
		t.Errorf("expires = %s, want unset", p.Expires)
	}
}

// MakeVerifiableDoc's only error is from json.Marshal of the document.
func TestMakeVerifiableDoc_RejectsUnmarshalableDoc(t *testing.T) {
	type cycle struct {
		Self *cycle `json:"self"`
	}
	loop := &cycle{}
	loop.Self = loop

	tests := []struct {
		name string
		doc  any
		want string
	}{
		{name: "channel", doc: make(chan int), want: "unsupported type: chan int"},
		{name: "function", doc: func() {}, want: "unsupported type: func()"},
		{name: "complex", doc: complex(1, 2), want: "unsupported type: complex128"},
		{name: "map key", doc: map[struct{ N int }]string{{}: "x"}, want: "object member name must be a string"},
		{name: "NaN", doc: math.NaN(), want: "unsupported value: NaN"},
		{name: "+Inf", doc: math.Inf(1), want: "unsupported value: +Inf"},
		{name: "cycle", doc: loop, want: "encountered a cycle"},
		{name: "marshal error", doc: refuseJSON{}, want: "refuse to marshal"},
		{name: "invalid raw JSON", doc: json.RawMessage(`{"id":`), want: "unexpected end of JSON input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vm := did.MustParseDIDURL(testKeyURL)
			vd, err := MakeVerifiableDoc(tt.doc, CryptoSuiteECDSAJCS2019, &vm)
			requireErrorContains(t, err, tt.want)
			if vd.Body != nil || vd.Proof.ProofType != "" {
				t.Errorf("MakeVerifiableDoc returned a partial doc with its error: %+v", vd)
			}
		})
	}
}

// --- Sign ---

func TestSign_RoundTrip(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			t.Parallel()
			signer, err := GenerateECDSASigner(curve)
			if err != nil {
				t.Fatalf("GenerateECDSASigner: %v", err)
			}
			vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
			parsed := mustParseDoc(t, mustSign(t, &vd, signer))
			requireNoError(t, parsed.Verify(signer.verifier()))
		})
	}
}

// After a successful Sign, the doc holds the new proof and verifies as is.
func TestSign_UpdatesDoc(t *testing.T) {
	signer := mustECDSASigner(t)
	vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
	signed := mustSign(t, &vd, signer)

	if len(vd.Proof.ProofValue) == 0 {
		t.Error("ProofValue is empty after Sign")
	}
	// Body gains the Data Integrity context, and is the signed document
	// without its proof.
	document, _ := signedFields(t, signed)
	delete(document, "proof")
	if want := mustMarshal(t, document); !bytes.Equal(vd.Body, want) {
		t.Errorf("Body = %s, want %s", vd.Body, want)
	}
	requireNoError(t, vd.Verify(signer.verifier()))
}

func TestSign_AddsDataIntegrityContext(t *testing.T) {
	const v2 = "https://www.w3.org/ns/credentials/v2"
	tests := []struct {
		name        string
		context     any // nil means the doc has no @context
		wantContext string
	}{
		{name: "absent", wantContext: `["` + DataIntegrityContext + `"]`},
		{name: "null", context: json.RawMessage("null"), wantContext: `["` + DataIntegrityContext + `"]`},
		{name: "string", context: v2, wantContext: `["` + v2 + `","` + DataIntegrityContext + `"]`},
		{name: "array", context: []any{v2}, wantContext: `["` + v2 + `","` + DataIntegrityContext + `"]`},
		{
			name:        "array with object",
			context:     []any{v2, map[string]any{"name": "https://schema.org/name"}},
			wantContext: `["` + v2 + `",{"name":"https://schema.org/name"},"` + DataIntegrityContext + `"]`,
		},
		{name: "already the string", context: DataIntegrityContext, wantContext: `"` + DataIntegrityContext + `"`},
		{name: "already in the array", context: []any{DataIntegrityContext, v2}, wantContext: `["` + DataIntegrityContext + `","` + v2 + `"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc := sampleDoc()
			if tt.context != nil {
				doc["@context"] = tt.context
			}
			signer := mustECDSASigner(t)
			vd := mustMakeVerifiableDoc(t, doc, CryptoSuiteECDSAJCS2019)
			signed := mustSign(t, &vd, signer)

			document, proof := signedFields(t, signed)
			requireRawField(t, document, "@context", tt.wantContext)
			requireRawField(t, proof, "@context", "")

			requireNoError(t, mustParseDoc(t, signed).Verify(signer.verifier()))
		})
	}
}

func TestSign_ProofTimestamps(t *testing.T) {
	created := time.Date(2026, 3, 28, 15, 40, 0, 0, time.UTC)
	expires := created.Add(24 * time.Hour)
	tests := []struct {
		name        string
		created     time.Time
		expires     time.Time
		wantCreated string // empty means the field must be absent
		wantExpires string // empty means the field must be absent
	}{
		{name: "created only", created: created, wantCreated: `"2026-03-28T15:40:00Z"`},
		{
			name:        "created and expires",
			created:     created,
			expires:     expires,
			wantCreated: `"2026-03-28T15:40:00Z"`,
			wantExpires: `"2026-03-29T15:40:00Z"`,
		},
		{name: "neither"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			signer := mustECDSASigner(t)
			vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
			vd.Proof.Created = tt.created
			vd.Proof.Expires = tt.expires
			signed := mustSign(t, &vd, signer)

			_, proof := signedFields(t, signed)
			requireRawField(t, proof, "created", tt.wantCreated)
			requireRawField(t, proof, "expires", tt.wantExpires)

			parsed := mustParseDoc(t, signed)
			if !parsed.Proof.Created.Equal(tt.created) || !parsed.Proof.Expires.Equal(tt.expires) {
				t.Errorf("parsed created, expires = %s, %s; want %s, %s",
					parsed.Proof.Created, parsed.Proof.Expires, tt.created, tt.expires)
			}
			// Verify while the proof is valid. Some cases expired in the past.
			requireNoError(t, parsed.VerifyAt(signer.verifier(), tt.created))
		})
	}
}

// A freshly made and signed doc writes created as whole-second UTC, such as
// "2026-03-28T15:40:00Z", and leaves expires out.
func TestSign_DefaultTimestampFormat(t *testing.T) {
	vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
	_, proof := signedFields(t, mustSign(t, &vd, mustECDSASigner(t)))

	wholeSecondUTC := regexp.MustCompile(`^"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"$`)
	if got := string(proof["created"]); !wholeSecondUTC.MatchString(got) {
		t.Errorf("created = %s, want whole-second UTC", got)
	}
	requireRawField(t, proof, "expires", "")
}

// Sign rejects a signer whose signature type does not match the cryptosuite.
// An unknown suite matches no signer.
func TestSign_RejectsSuiteMismatch(t *testing.T) {
	ecdsaSigner := mustECDSASigner(t)
	eddsaSigner := stubSigner{kind: SigTypeEDDSA}
	tests := []struct {
		name   string
		suite  CryptoSuiteType
		signer Signer
		want   string
	}{
		{name: "ECDSA signer, eddsa-jcs-2022", suite: CryptoSuiteEDDSAJCS2022, signer: ecdsaSigner, want: "signer type ECDSA does not match cryptosuite eddsa-jcs-2022"},
		{name: "ECDSA signer, eddsa-rdfc-2022", suite: CryptoSuiteEDDSARDFC2022, signer: ecdsaSigner, want: "signer type ECDSA does not match cryptosuite eddsa-rdfc-2022"},
		{name: "ECDSA signer, unknown suite", suite: CryptoSuiteUnknown, signer: ecdsaSigner, want: "signer type ECDSA does not match cryptosuite unknown crypto suite"},
		{name: "EdDSA signer, ecdsa-jcs-2019", suite: CryptoSuiteECDSAJCS2019, signer: eddsaSigner, want: "signer type EdDSA does not match cryptosuite ecdsa-jcs-2019"},
		{name: "EdDSA signer, ecdsa-rdfc-2019", suite: CryptoSuiteECDSARDFC2019, signer: eddsaSigner, want: "signer type EdDSA does not match cryptosuite ecdsa-rdfc-2019"},
		{name: "unknown signer type", suite: CryptoSuiteECDSAJCS2019, signer: stubSigner{kind: SigType(99)}, want: "signer type unknown signature type does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), tt.suite)
			requireSignError(t, &vd, tt.signer, tt.want)
		})
	}
}

// The RDFC suites pass the signer check, but this package cannot hash them.
func TestSign_UnsupportedCryptoSuite(t *testing.T) {
	tests := []struct {
		suite  CryptoSuiteType
		signer Signer
	}{
		{suite: CryptoSuiteECDSARDFC2019, signer: mustECDSASigner(t)},
		{suite: CryptoSuiteEDDSARDFC2022, signer: stubSigner{kind: SigTypeEDDSA}},
	}
	for _, tt := range tests {
		t.Run(tt.suite.String(), func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), tt.suite)
			requireSignError(t, &vd, tt.signer, "hashing document: unsupported cryptosuite "+tt.suite.String())
		})
	}
}

// Sign must refuse to produce a doc that ParseDoc would reject.
func TestSign_RejectsInvalidProofConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Proof)
		want   string
	}{
		{name: "wrong type", mutate: func(p *Proof) { p.ProofType = "Ed25519Signature2020" }, want: `unsupported proof type "Ed25519Signature2020"`},
		{name: "empty type", mutate: func(p *Proof) { p.ProofType = "" }, want: `unsupported proof type ""`},
		{name: "wrong purpose", mutate: func(p *Proof) { p.ProofPurpose = "authentication" }, want: `unsupported proof purpose "authentication"`},
		{name: "empty purpose", mutate: func(p *Proof) { p.ProofPurpose = "" }, want: `unsupported proof purpose ""`},
		{name: "no verification method", mutate: func(p *Proof) { p.VerificationMethod = nil }, want: "proof has no verificationMethod"},
		{name: "expires at created", mutate: func(p *Proof) { p.Expires = p.Created }, want: "proof expires at or before it was created"},
		{name: "expires before created", mutate: func(p *Proof) { p.Expires = p.Created.Add(-time.Second) }, want: "proof expires at or before it was created"},
	}
	signer := mustECDSASigner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
			tt.mutate(&vd.Proof)
			requireSignError(t, &vd, signer, tt.want)
		})
	}
}

// MakeVerifiableDoc encodes any JSON value. Sign then needs an object, so it
// can embed the proof.
func TestSign_RejectsNonObjectBody(t *testing.T) {
	var nilPtr *struct{ ID int }
	tests := []struct {
		name string
		doc  any
		want string
	}{
		{name: "nil", doc: nil, want: "document is null"},
		{name: "nil pointer", doc: nilPtr, want: "document is null"},
		{name: "nil slice", doc: []int(nil), want: "document is null"},
		{name: "raw null", doc: json.RawMessage(`null`), want: "document is null"},
		{name: "number", doc: 101, want: "parsing document: json: cannot unmarshal number"},
		{name: "string", doc: "Alice", want: "parsing document: json: cannot unmarshal string"},
		{name: "bool", doc: true, want: "parsing document: json: cannot unmarshal bool"},
		{name: "array", doc: []int{1, 2}, want: "parsing document: json: cannot unmarshal array"},
	}
	signer := mustECDSASigner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, tt.doc, CryptoSuiteECDSAJCS2019)
			requireSignError(t, &vd, signer, tt.want)
		})
	}
}

// encoding/json accepts some documents that JCS cannot canonicalize. Sign
// rejects them before it changes anything, as ParseDoc does.
func TestSign_RejectsUncanonicalizableBody(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "duplicate key", raw: `{"id":1,"id":2}`, want: "Duplicate key"},
		{name: "number out of range", raw: `{"n":1e9999}`, want: "Number out of range"},
		{name: "lone surrogate", raw: `{"name":"\uD800"}`, want: "Missing surrogate"},
	}
	signer := mustECDSASigner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, json.RawMessage(tt.raw), CryptoSuiteECDSAJCS2019)
			requireSignError(t, &vd, signer, "parsing document: "+tt.want)
		})
	}
}

// A Body set by hand that is not JSON fails before anything is signed.
func TestSign_RejectsInvalidBody(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "nil", body: nil, want: "No JSON data provided"},
		{name: "empty", body: []byte{}, want: "Unexpected EOF reached"},
		{name: "truncated", body: []byte(`{"id":`), want: "Unexpected EOF reached"},
		{name: "trailing junk", body: []byte(`{"id":1}x`), want: "Improperly terminated JSON object"},
	}
	signer := mustECDSASigner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
			vd.Body = tt.body
			requireSignError(t, &vd, signer, "parsing document: "+tt.want)
		})
	}
}

// An ECDSA key whose scalar is outside 1 to N-1 cannot sign. A signer that
// fails on its own is reported the same way.
func TestSign_InvalidSigner(t *testing.T) {
	withScalar := func(d *big.Int) Signer {
		signer := mustECDSASigner(t)
		signer.signKey.D = d
		return signer
	}
	tests := []struct {
		name   string
		signer Signer
		want   string
	}{
		{name: "zero scalar", signer: withScalar(big.NewInt(0)), want: "signing document: signing: ecdsa: private key scalar is zero or negative"},
		{name: "negative scalar", signer: withScalar(big.NewInt(-1)), want: "signing document: signing: ecdsa: private key scalar is zero or negative"},
		{name: "scalar too large", signer: withScalar(new(big.Int).Lsh(big.NewInt(1), 256)), want: "signing document: signing: ecdsa: private key scalar too large"},
		{name: "sign error", signer: stubSigner{kind: SigTypeECDSA, signErr: errors.New("key unavailable")}, want: "signing document: key unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
			requireSignError(t, &vd, tt.signer, tt.want)
		})
	}
}

// Signing a body that already has a proof would hash the old proof into the
// body and then overwrite it, giving a doc that can never verify.
func TestSign_RejectsBodyWithProof(t *testing.T) {
	doc := map[string]any{"id": 101, "proof": map[string]any{"type": "DataIntegrityProof"}}
	vd := mustMakeVerifiableDoc(t, doc, CryptoSuiteECDSAJCS2019)
	requireSignError(t, &vd, mustECDSASigner(t), "document already has a proof")
}

// Sign must not overwrite an existing signature, whether the doc was signed
// here or parsed from a signed document.
func TestSign_RejectsSignedDoc(t *testing.T) {
	signer := mustECDSASigner(t)
	signedHere := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
	parsed := mustParseDoc(t, mustSign(t, &signedHere, signer))

	for name, vd := range map[string]VerifiableDoc{"signed here": signedHere, "parsed": parsed} {
		t.Run(name, func(t *testing.T) {
			requireSignError(t, &vd, signer, "document is already signed")
		})
	}
}

// --- Verify ---

func TestVerifyAt_ProofTimes(t *testing.T) {
	created := time.Date(2026, 3, 28, 15, 40, 0, 0, time.UTC)
	expires := created.Add(24 * time.Hour)
	vd, verifier := signedTestDoc(t, sampleDoc(), created, expires)

	tests := []struct {
		name    string
		at      time.Time
		wantErr error
	}{
		{name: "before created", at: created.Add(-time.Second), wantErr: ErrProofNotYetValid},
		{name: "at created", at: created},
		{name: "between created and expires", at: created.Add(time.Hour)},
		{name: "just before expires", at: expires.Add(-time.Nanosecond)},
		{name: "at expires", at: expires, wantErr: ErrProofExpired},
		{name: "after expires", at: expires.Add(time.Hour), wantErr: ErrProofExpired},
		{name: "same instant in another zone", at: created.In(time.FixedZone("UTC+8", 8*60*60))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := vd.VerifyAt(verifier, tt.at)
			if tt.wantErr == nil {
				requireNoError(t, err)
				return
			}
			requireErrorIs(t, err, tt.wantErr)
		})
	}
}

// created and expires are both optional. A missing one sets no bound.
func TestVerifyAt_OptionalProofTimes(t *testing.T) {
	created := time.Date(2026, 3, 28, 15, 40, 0, 0, time.UTC)
	farPast := created.AddDate(-100, 0, 0)
	farFuture := created.AddDate(100, 0, 0)
	tests := []struct {
		name    string
		created time.Time
		at      time.Time
	}{
		{name: "no expires, far future", created: created, at: farFuture},
		{name: "no created, far past", at: farPast},
		{name: "no created, far future", at: farFuture},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd, verifier := signedTestDoc(t, sampleDoc(), tt.created, time.Time{})
			requireNoError(t, vd.VerifyAt(verifier, tt.at))
		})
	}
}

func TestVerify_UsesCurrentTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name    string
		created time.Time
		expires time.Time
		wantErr error
	}{
		{name: "valid now", created: now.Add(-time.Hour), expires: now.Add(time.Hour)},
		{name: "expired", created: now.Add(-2 * time.Hour), expires: now.Add(-time.Hour), wantErr: ErrProofExpired},
		{name: "created in the future", created: now.Add(time.Hour), wantErr: ErrProofNotYetValid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd, verifier := signedTestDoc(t, sampleDoc(), tt.created, tt.expires)
			err := vd.Verify(verifier)
			if tt.wantErr == nil {
				requireNoError(t, err)
				return
			}
			requireErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestVerify_RejectsSuiteMismatch(t *testing.T) {
	ecdsaDoc, _ := signedTestDoc(t, sampleDoc(), time.Time{}, time.Time{})
	t.Run("ECDSA doc, EdDSA key", func(t *testing.T) {
		requireErrorContains(t, ecdsaDoc.Verify(mustVerifier(t, vectorEd25519.publicKey)), "verifier type EdDSA does not match cryptosuite ecdsa-jcs-2019")
	})
	t.Run("EdDSA doc, ECDSA key", func(t *testing.T) {
		requireErrorContains(t, vectorDoc(t, vectorEd25519).Verify(mustVerifier(t, vectorP256.publicKey)), "verifier type ECDSA does not match cryptosuite eddsa-jcs-2022")
	})
}

func TestVerify_UnsupportedCryptoSuite(t *testing.T) {
	vd := mustParseDoc(t, []byte(rdfcExampleDoc))
	requireErrorContains(t, vd.Verify(mustVerifier(t, vectorEd25519.publicKey)), "unsupported cryptosuite eddsa-rdfc-2022")
}

func TestVerify_NilVerifier(t *testing.T) {
	vd, _ := signedTestDoc(t, sampleDoc(), time.Time{}, time.Time{})
	requireErrorContains(t, vd.Verify(nil), "no verifier given")
}

// A malformed signature is an invalid signature, and the error says why.
func TestVerify_MalformedSignature(t *testing.T) {
	vd := vectorDoc(t, vectorP256)
	vd.Proof.ProofValue = vd.Proof.ProofValue[:10]
	err := vd.Verify(mustVerifier(t, vectorP256.publicKey))
	requireErrorIs(t, err, ErrInvalidSignature)
	requireErrorContains(t, err, "wrong signature size")
}

// --- End to end with a DID document ---

// A signer publishes its key in a DID document. A verifier parses the signed
// doc, finds the key the proof names, and verifies.
func TestSignAndVerifyWithDID(t *testing.T) {
	signer := mustECDSASigner(t)
	keyURL := did.MustParseDIDURL(testKeyURL)
	vm, err := did.NewVerificationMethod(keyURL, ssi.JsonWebKey2020, keyURL.DID, &signer.signKey.PublicKey)
	if err != nil {
		t.Fatalf("did.NewVerificationMethod: %v", err)
	}
	published := &did.Document{Context: []any{did.DIDContextV1URI()}, ID: keyURL.DID}
	published.AddAssertionMethod(vm)

	vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuiteECDSAJCS2019)
	signed := mustSign(t, &vd, signer)

	// The verifier receives both documents as JSON.
	didDoc, err := did.ParseDocument(string(mustMarshal(t, published)))
	if err != nil {
		t.Fatalf("did.ParseDocument: %v", err)
	}
	received := mustParseDoc(t, signed)
	verifier, err := GetAssertionVerifier(didDoc, received.Proof.VerificationMethod)
	if err != nil {
		t.Fatalf("GetAssertionVerifier: %v", err)
	}
	requireNoError(t, received.Verify(verifier))
}

// This doc was signed by an earlier version of this package. Its created
// time has a zone offset and fractional seconds, and it has a non-standard
// "expiry" field. Both are covered by the signature, so it still verifies.
func TestVerifyLegacyDocFromDID(t *testing.T) {
	const signed = `{"id":101,"name":"Alice","proof":{"type":"DataIntegrityProof","proofPurpose":"assertionMethod","cryptosuite":"ecdsa-jcs-2019","verificationMethod":"did:web:example.com:user:101#key-1","proofValue":"z41BkGy5VEDeqrKqFwea5br1gmaZKT9YESoCVz2ESsvoFScazx6Le8VytRisoKjkzD63aF8DH38U74sjaBLu7CMzF","created":"2026-10-06T15:06:41.070247+08:00","expiry":"0001-01-01T00:00:00Z"}}`
	const didDocument = `{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:example.com:user:101",
  "assertionMethod": ["did:web:example.com:user:101#key-1"],
  "verificationMethod": [
    {
      "id": "did:web:example.com:user:101#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com:user:101",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "og9qNE10V4aSHCTMJFCAcciUfbUqk_pe4MXlqVqEEow",
        "y": "NirPmr7CcLI6GVlNNCvOrA7YKfnj40VT8bEKMZ591QU"
      }
    }
  ]
}`
	vd := mustParseDoc(t, []byte(signed))
	didDoc, err := did.ParseDocument(didDocument)
	if err != nil {
		t.Fatalf("did.ParseDocument: %v", err)
	}
	if vd.Proof.VerificationMethod.DID != didDoc.ID {
		t.Fatalf("proof DID = %s, DID document ID = %s", vd.Proof.VerificationMethod.DID, didDoc.ID)
	}
	verifier, err := GetAssertionVerifier(didDoc, vd.Proof.VerificationMethod)
	if err != nil {
		t.Fatalf("GetAssertionVerifier: %v", err)
	}
	requireNoError(t, vd.Verify(verifier))
}
