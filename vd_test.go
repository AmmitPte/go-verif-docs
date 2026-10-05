package verifdocs

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
)

const ExampleDoc = `{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/data-integrity/v1"
  ],
  "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321",
  "type": "Person",
  "name": "Alice",
  "preferredUsername": "alice",
  "summary": "Building a decentralized social app",
  "icon": {
    "type": "Image",
    "url": "https://example.com/alice.jpg"
  },
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

func TestParseProof(t *testing.T) {
	var document map[string]json.RawMessage
	_ = json.Unmarshal([]byte(ExampleDoc), &document)
	var proof Proof
	if err := json.Unmarshal(document["proof"], &proof); err != nil {
		t.Errorf("Could not parse proof: %s", err)
		return
	}
	if proof.ProofType != "DataIntegrityProof" {
		t.Errorf("Proof type does not match expected, got %s expected %s", proof.ProofType, "DataIntegrityProof")
	}
	if proof.ProofPurpose != "assertionMethod" {
		t.Errorf("Proof purpose does not match expected, got %s expected %s", proof.ProofPurpose, "assertionMethod")
	}
	if proof.CryptoSuite != CryptoSuite_EDDSA_RDFC_2022 {
		t.Errorf("Cryptosuite does not match expected, got %s expected %s", proof.CryptoSuite, CryptoSuiteType(CryptoSuite_EDDSA_RDFC_2022))
	}
	if proof.VerificationMethod.String() != "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321#z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321" {
		t.Errorf("Verification method does not match expected, got %s expected %s", proof.VerificationMethod.String(), "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321#z6MkpTHR8VNsBxYAAWHut2Geadd9jFuXzM2yZjnjJa3321")
	}
	expValue := []byte{
		0x00, 0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27,
		0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6, 0xf0, 0xfb,
		0x50, 0xeb, 0xb8, 0x8f, 0x18, 0xc2, 0x9b, 0x7d,
		0x93,
	}
	if !bytes.Equal(proof.ProofValue, expValue) {
		t.Errorf("Proof value not as expected, got %x expectd %x", proof.ProofValue, expValue)
	}
	exp_time := time.Date(2026, 03, 28, 15, 40, 0, 0, time.UTC)
	if proof.Created != exp_time {
		t.Errorf("Proof creation time not as expected: got %s expected %s", proof.Created, exp_time)
	}
}

const (
	exCredentialWithoutProof = `{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {
        "id": "did:example:abcdefgh",
        "alumniOf": "The School of Examples"
    }
}`
	exProofOptions = `{
  "type": "DataIntegrityProof",
  "cryptosuite": "ecdsa-jcs-2019",
  "created": "2023-02-24T23:36:38Z",
  "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
  "proofPurpose": "assertionMethod",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ]
}`
	exCredentialJCSCanon = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"credentialSubject":{"alumniOf":"The School of Examples","id":"did:example:abcdefgh"},"description":"A minimum viable example of an Alumni Credential.","id":"urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33","issuer":"https://vc.example/issuers/5678","name":"Alumni Credential","type":["VerifiableCredential","AlumniCredential"],"validFrom":"2023-01-01T00:00:00Z"}`
	exProofJCSCanon      = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"created":"2023-02-24T23:36:38Z","cryptosuite":"ecdsa-jcs-2019","proofPurpose":"assertionMethod","type":"DataIntegrityProof","verificationMethod":"did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"}`
	exFullCredential     = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": [
    "VerifiableCredential",
    "AlumniCredential"
  ],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jcs-2019",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "proofValue": "z5ptCet75SaEgzG4v4zJhbJtfNi74Wv7Fq15hhKouJQQjEPQvPZKaYxcMXAMLPQS2FXrkCWokNJkFVkwxNzZfD5oT"
  }
}`
)

func TestJCSCanonicalize(t *testing.T) {
	// First just check that our canonicalizer works
	bodyCanon, err := jcs.Transform([]byte(exCredentialWithoutProof))
	if err != nil {
		t.Errorf("Error canonicalizing body: %s", err)
	} else if string(bodyCanon) != exCredentialJCSCanon {
		t.Errorf("Canonicalized body does not match expected.\nGot: %s\nExpected: %s\n", string(bodyCanon), exCredentialJCSCanon)
	}

	proofCanon, err := jcs.Transform([]byte(exProofOptions))
	if err != nil {
		t.Errorf("Error canonicalizing proof options: %s", err)
	} else if string(proofCanon) != exProofJCSCanon {
		t.Errorf("Canonicalized proof options does not match expected.\nGot: %s\nExpected: %s\n", string(proofCanon), exProofJCSCanon)
	}
}

func sha256hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha384hash(data []byte) []byte {
	sum := sha512.Sum384(data)
	return sum[:]
}

func TestJCSHash(t *testing.T) {
	hasher := JCSHasher(sha256hash)
	expHash := "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec2559b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
	result, err := hasher.Hash([]byte(exCredentialWithoutProof), []byte(exProofOptions))
	if err != nil {
		t.Errorf("Error hashing doc: %s", err)
	} else if hex.EncodeToString(result) != expHash {
		t.Errorf("Resulting hash does not match expected.\nGot: %s\nExpected: %s", hex.EncodeToString(result), expHash)
	}
}

func TestGetHash_ECDSAJCS(t *testing.T) {
	doc, err := ParseDoc([]byte(exFullCredential))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	if doc.Proof.CryptoSuite != CryptoSuite_ECDSA_JCS_2019 {
		t.Fatalf("cryptosuite = %s, want ecdsa-jcs-2019", doc.Proof.CryptoSuite)
	}

	// P-256: SHA-256 of the canonical proof, then SHA-256 of the canonical document.
	const want = "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec25" +
		"59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"

	got, err := doc.GetHash(sha256hash)
	if err != nil {
		t.Fatalf("GetHash: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Errorf("GetHash = %x, want %s", got, want)
	}
}

// P-384 ecdsa-jcs-2019 vectors from
// https://w3c.github.io/vc-di-ecdsa/#representation-ecdsa-jcs-2019-with-curve-p-384
// Parsing succeeds. GetHash and Verify still use SHA-256, so those tests fail.
const (
	exP384PublicKey = "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ"
	// SHA-384(canonical proof) || SHA-384(canonical document).
	exP384CombinedHash = "83e5057817abb0c6872eafeaba1a9e53893c58eeb7414fb6d8aa3fa8c7917f7a" +
		"d4792890b257c598baa17f4fbe6d183c" +
		"3e0be671cc1881035d463158c80921973dab3534d4f8dfacf4ff2725a4115eb7" +
		"18e49d66de0e90e7365cd6062abf2259"
	exP384Signature = "8b7462ce62db0c8ff19878c4b3561c49eb71b4a743086b6d5b0eda70ecf0afc5" +
		"a03fd88eb207d66b262ed87fd200a4e8e62716e0b329c032b67726b4b0fc737a" +
		"44c1cefdba2fdccb3ece74cc5845aaa93374455a726f6ee4f5f30da9427f608a"
	exP384Credential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jcs-2019",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "proofValue": "zq3EuTeLiGurmB2JR5oL8oWEsT7u2tba4HT1oZbiMYWc5qzsoW2kLYcBcF4HM5vCpJyTkceULKrVXuJQkXeN5seL4uXrFNFRMm53GWy1Yrto8rTWxZi9DkNeWP7yUPs7ELAm"
  }
}`
)

func TestParseDoc_ECDSAJCS_P384(t *testing.T) {
	doc := mustParseCredential(t, exP384Credential)

	if doc.Proof.CryptoSuite != CryptoSuite_ECDSA_JCS_2019 {
		t.Errorf("cryptosuite = %s, want ecdsa-jcs-2019", doc.Proof.CryptoSuite)
	}
	if doc.Proof.ProofType != "DataIntegrityProof" {
		t.Errorf("proof type = %q, want DataIntegrityProof", doc.Proof.ProofType)
	}
	if doc.Proof.ProofPurpose != "assertionMethod" {
		t.Errorf("proof purpose = %q, want assertionMethod", doc.Proof.ProofPurpose)
	}
	if doc.Proof.VerificationMethod.ID != exP384PublicKey {
		t.Errorf("verification method = %s, want %s", doc.Proof.VerificationMethod.ID, exP384PublicKey)
	}
	if got := hex.EncodeToString(doc.Proof.ProofValue); got != exP384Signature {
		t.Errorf("proof value = %s, want %s", got, exP384Signature)
	}
}

func TestGetHash_ECDSAJCS_P384(t *testing.T) {
	doc := mustParseCredential(t, exP384Credential)

	got, err := doc.GetHash(sha384hash)
	if err != nil {
		t.Fatalf("GetHash: %v", err)
	}
	if hex.EncodeToString(got) != exP384CombinedHash {
		t.Errorf("GetHash = %x, want %s", got, exP384CombinedHash)
	}
}

func TestVerify_ECDSAJCS_P384(t *testing.T) {
	doc := mustParseCredential(t, exP384Credential)
	verifier, err := VerifierFromMultikey(exP384PublicKey)
	if err != nil {
		t.Fatalf("VerifierFromMultikey: %v", err)
	}

	ok, err := doc.Verify(verifier)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false")
	}
}

func mustParseCredential(t *testing.T, document string) VerifiableDoc {
	t.Helper()
	doc, err := ParseDoc([]byte(document))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	return doc
}

func TestParseVerifDoc(t *testing.T) {
	doc, err := ParseDoc([]byte(exFullCredential))
	if err != nil {
		t.Errorf("Error parsing verif doc: %s", err)
		return
	}

	bodyBytes, _ := json.Marshal(doc.Body)
	bodyJCS, err := jcs.Transform(bodyBytes)
	if err != nil {
		t.Errorf("Error canonicalizing body: %s", err)
	} else if string(bodyJCS) != exCredentialJCSCanon {
		t.Errorf("Body does not match expected:\nGot %s\nExpected %s", string(bodyJCS), exCredentialJCSCanon)
	}

	// have to remove proof value from raw proof
	var proof map[string]json.RawMessage
	if err := json.Unmarshal(doc.RawProof, &proof); err != nil {
		t.Errorf("Error parsing raw proof: %s", err)
	}
	delete(proof, "proofValue")
	proofBytes, _ := json.Marshal(proof)
	proofJCS, err := jcs.Transform(proofBytes)
	if err != nil {
		t.Errorf("Error canonicalizing proof: %s", err)
	} else if string(proofJCS) != exProofJCSCanon {
		t.Errorf("Proof does not match expected:\nGot %s\nExpected %s", string(bodyJCS), exCredentialJCSCanon)
	}

	if doc.Proof.ProofType != "DataIntegrityProof" {
		t.Errorf("Proof type doesn't match expected, got %s, expected %s", doc.Proof.ProofType, "DataIntegrityProof")
	}
	const expID = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
	if doc.Proof.VerificationMethod.ID != expID {
		t.Errorf("Proof ID doesn't match expected.\nGot: %s\nExp: %s", doc.Proof.VerificationMethod.ID, expID)
	}

	sigHex := hex.EncodeToString(doc.Proof.ProofValue)
	const expSig = "f15c3b599eb9b3cad05df9d8e8b39a70a86375833b53743c764ac0a88c4457d60707fd7d073e03d906130631d87803f80a9824dc9939632ba92d418181be9d16"
	if sigHex != expSig {
		t.Errorf("Sig does not match expected,\nGot: %s\nExp: %s", sigHex, expSig)
	}
}

func TestParseDoc_MissingProof(t *testing.T) {
	requireParseDocError(t, `{"id":"urn:example:1"}`, "Doc has no proof section")
}

func TestParseDoc_MalformedJSON(t *testing.T) {
	requireParseDocError(t, `{"id":`, "Error parsing doc:")
}

func TestParseDoc_MalformedProof(t *testing.T) {
	requireParseDocError(t, `{"id":"urn:example:1","proof":{"type":}}`, "Error parsing doc:")
}

func TestParseDoc_MalformedNonProofField(t *testing.T) {
	// credentialSubject is not valid JSON. ParseDoc only decodes the top-level
	// object and leaves every other field raw, so this still parses.
	const document = `{
		"id": "urn:example:1",
		"credentialSubject": "{not: valid}",
		"proof": {
			"type": "DataIntegrityProof",
			"proofPurpose": "assertionMethod"
		}
	}`

	doc, err := ParseDoc([]byte(document))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	got, ok := doc.Body["credentialSubject"]
	if !ok {
		t.Fatal("credentialSubject was dropped")
	}
	const want = `"{not: valid}"`
	if string(got) != want {
		t.Errorf("credentialSubject = %s, want %s", got, want)
	}
	if _, ok := doc.Body["proof"]; ok {
		t.Error("proof was left in the body")
	}
	if doc.Proof.ProofType != "DataIntegrityProof" || doc.Proof.ProofPurpose != "assertionMethod" {
		t.Errorf("proof = type %q purpose %q", doc.Proof.ProofType, doc.Proof.ProofPurpose)
	}
}

func TestParseDoc_ProofDoesNotUnmarshal(t *testing.T) {
	tests := []struct {
		name  string
		proof string
	}{
		{name: "array", proof: `[1, 2, 3]`},
		{
			name:  "unknown cryptosuite",
			proof: `{"type":"DataIntegrityProof","proofPurpose":"assertionMethod","cryptosuite":"nope"}`,
		},
		{
			name:  "created",
			proof: `{"type":"DataIntegrityProof","proofPurpose":"assertionMethod","created":"yesterday"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requireParseDocError(t, docWithProof(tt.proof), "Error parsing doc proof")
		})
	}
}

func TestParseDoc_WrongTypeOrPurpose(t *testing.T) {
	tests := []struct {
		name  string
		proof string
		want  string
	}{
		{
			name:  "type",
			proof: `{"type":"Ed25519Signature2020","proofPurpose":"assertionMethod"}`,
			want:  "Unsupported proof type: Ed25519Signature2020",
		},
		{
			name:  "purpose",
			proof: `{"type":"DataIntegrityProof","proofPurpose":"authentication"}`,
			want:  "Unsupported proof type: DataIntegrityProof",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requireParseDocError(t, docWithProof(tt.proof), tt.want)
		})
	}
}

func docWithProof(proof string) string {
	return `{"id":"urn:example:1","proof":` + proof + `}`
}

func requireParseDocError(t *testing.T, document, want string) {
	t.Helper()
	_, err := ParseDoc([]byte(document))
	if err == nil {
		t.Fatal("ParseDoc succeeded")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}

func TestVerifDocVerify(t *testing.T) {
	doc, err := ParseDoc([]byte(exFullCredential))
	if err != nil {
		t.Errorf("Error parsing verif doc: %s", err)
		return
	}

	// in practice would check verificationMethod ID and retrieve,
	// but for test just assume we have the correct key.

	expHash := "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec2559b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
	docHash, err := doc.GetHash(sha256hash)
	if err != nil {
		t.Errorf("Error hashing doc: %s", err)
	} else if hex.EncodeToString(docHash) != expHash {
		t.Errorf("Doc hash does not match expected.\nGot: %s\nExp: %s", hex.EncodeToString(docHash), expHash)
	}

	const key = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
	verifier, err := VerifierFromMultikey(key)
	if err != nil {
		t.Errorf("Error getting verif key: %s", err)
	}
	if key != doc.Proof.VerificationMethod.ID {
		t.Errorf("Verif key does not match expected.\nGot: %s\nExp: %s", doc.Proof.VerificationMethod.ID, key)
	}
	result, err := doc.Verify(verifier)
	if err != nil {
		t.Errorf("Error verifying doc: %s", err)
	} else if !result {
		t.Errorf("Doc verification failed.")
	}
}

func TestCryptoSuiteType_StringAndParse(t *testing.T) {
	tests := []struct {
		suite CryptoSuiteType
		text  string
	}{
		{CryptoSuite_ECDSA_JCS_2019, "ecdsa-jcs-2019"},
		{CryptoSuite_ECDSA_RDFC_2019, "ecdsa-rdfc-2019"},
		{CryptoSuite_EDDSA_JCS_2022, "eddsa-jcs-2022"},
		{CryptoSuite_EDDSA_RDFC_2022, "eddsa-rdfc-2022"},
	}
	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			t.Parallel()

			if got := tt.suite.String(); got != tt.text {
				t.Errorf("String() = %q, want %q", got, tt.text)
			}
			if got := ParseCryptoSuite(tt.text); got != tt.suite {
				t.Errorf("ParseCryptoSuite(%q) = %v, want %v", tt.text, got, tt.suite)
			}

			var parsed CryptoSuiteType
			if err := parsed.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText(%q): %v", tt.text, err)
			}
			if parsed != tt.suite {
				t.Errorf("UnmarshalText(%q) = %v, want %v", tt.text, parsed, tt.suite)
			}
		})
	}
}

func TestCryptoSuiteType_InvalidString(t *testing.T) {
	const invalid = "not-a-suite"

	if got := ParseCryptoSuite(invalid); got != CryptoSuite_Unknown {
		t.Errorf("ParseCryptoSuite(%q) = %v, want %v", invalid, got, CryptoSuite_Unknown)
	}
	if got := CryptoSuiteType(CryptoSuite_Unknown).String(); got != "Unknown crypto suite" {
		t.Errorf("Unknown.String() = %q, want %q", got, "Unknown crypto suite")
	}

	suite := CryptoSuiteType(CryptoSuite_ECDSA_JCS_2019)
	err := suite.UnmarshalText([]byte(invalid))
	if err == nil {
		t.Fatal("UnmarshalText succeeded for an invalid suite")
	}
	if !strings.Contains(err.Error(), invalid) {
		t.Errorf("error = %q, want it to mention %q", err, invalid)
	}
	if suite != CryptoSuite_ECDSA_JCS_2019 {
		t.Errorf("suite = %v after failed UnmarshalText, want it unchanged", suite)
	}
}
