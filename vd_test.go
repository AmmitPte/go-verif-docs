package verifdocs

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/nuts-foundation/go-did/did"
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

// eddsa-jcs-2022 vectors from Appendix B.3 of
// https://w3c.github.io/vc-di-eddsa/#representation-eddsa-jcs-2022
// The unsigned credential is exCredentialWithoutProof; its canonical form is
// exCredentialJCSCanon. Only the proof options differ from the P-256 vector.
const (
	exEd25519PublicKey = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
	exEd25519ProofHash = "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db"
	exEd25519DocHash   = "59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19"
	exEd25519Signature = "407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b803" +
		"51da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808"
	exEd25519ProofCanon   = `{"@context":["https://www.w3.org/ns/credentials/v2","https://www.w3.org/ns/credentials/examples/v2"],"created":"2023-02-24T23:36:38Z","cryptosuite":"eddsa-jcs-2022","proofPurpose":"assertionMethod","type":"DataIntegrityProof","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"}`
	exEd25519ProofOptions = `{
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "created": "2023-02-24T23:36:38Z",
  "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "proofPurpose": "assertionMethod",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ]
}`
	exEd25519Credential = `{
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
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2023-02-24T23:36:38Z",
    "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
    "proofPurpose": "assertionMethod",
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "proofValue": "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX"
  }
}`
)

func TestJCSCanonicalize_EDDSA(t *testing.T) {
	proofCanon, err := jcs.Transform([]byte(exEd25519ProofOptions))
	if err != nil {
		t.Fatalf("canonicalizing proof options: %v", err)
	}
	if string(proofCanon) != exEd25519ProofCanon {
		t.Errorf("canonical proof = %s, want %s", proofCanon, exEd25519ProofCanon)
	}
}

func TestJCSHash_EDDSA(t *testing.T) {
	result, err := JCSHasher(sha256hash).Hash([]byte(exCredentialWithoutProof), []byte(exEd25519ProofOptions))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	got := hex.EncodeToString(result)
	if len(got) != len(exEd25519ProofHash)+len(exEd25519DocHash) {
		t.Fatalf("hash length = %d hex chars, want %d", len(got), len(exEd25519ProofHash)+len(exEd25519DocHash))
	}
	if got[:len(exEd25519ProofHash)] != exEd25519ProofHash {
		t.Errorf("proof hash = %s, want %s", got[:len(exEd25519ProofHash)], exEd25519ProofHash)
	}
	if got[len(exEd25519ProofHash):] != exEd25519DocHash {
		t.Errorf("document hash = %s, want %s", got[len(exEd25519ProofHash):], exEd25519DocHash)
	}
}

func TestParseDoc_EDDSAJCS(t *testing.T) {
	doc := mustParseCredential(t, exEd25519Credential)

	if doc.Proof.CryptoSuite != CryptoSuite_EDDSA_JCS_2022 {
		t.Errorf("cryptosuite = %s, want eddsa-jcs-2022", doc.Proof.CryptoSuite)
	}
	if doc.Proof.ProofType != "DataIntegrityProof" {
		t.Errorf("proof type = %q, want DataIntegrityProof", doc.Proof.ProofType)
	}
	if doc.Proof.ProofPurpose != "assertionMethod" {
		t.Errorf("proof purpose = %q, want assertionMethod", doc.Proof.ProofPurpose)
	}
	if doc.Proof.VerificationMethod.ID != exEd25519PublicKey {
		t.Errorf("verification method = %s, want %s", doc.Proof.VerificationMethod.ID, exEd25519PublicKey)
	}
	if got := hex.EncodeToString(doc.Proof.ProofValue); got != exEd25519Signature {
		t.Errorf("proof value = %s, want %s", got, exEd25519Signature)
	}
	if bytes.Contains(doc.Body, []byte(`"proof"`)) {
		t.Error("proof was left in the body")
	}
}

func TestGetHash_EDDSAJCS(t *testing.T) {
	doc := mustParseCredential(t, exEd25519Credential)

	got, err := doc.GetHash(sha256hash)
	if err != nil {
		t.Fatalf("GetHash: %v", err)
	}
	want := exEd25519ProofHash + exEd25519DocHash
	if hex.EncodeToString(got) != want {
		t.Errorf("GetHash = %x, want %s", got, want)
	}
}

func TestVerify_EDDSAJCS(t *testing.T) {
	doc := mustParseCredential(t, exEd25519Credential)
	verifier := mustVerifier(t, exEd25519PublicKey)
	if verifier.sigType() != SigType_EDDSA {
		t.Fatalf("sigType = %v, want EdDSA", verifier.sigType())
	}

	ok, err := doc.Verify(verifier)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false")
	}
}

func TestVerify_EDDSAJCS_RejectsTampering(t *testing.T) {
	verifier := mustVerifier(t, exEd25519PublicKey)
	tests := []struct {
		name    string
		mutate  func(*testing.T, *VerifiableDoc)
		wantErr string
	}{
		{
			name: "body",
			mutate: func(t *testing.T, doc *VerifiableDoc) {
				const name = `"Alumni Credential"`
				updated := bytes.Replace(doc.Body, []byte(name), []byte(`"Tampered"`), 1)
				if bytes.Equal(updated, doc.Body) {
					t.Fatalf("body has no %s to tamper", name)
				}
				doc.Body = updated
			},
		},
		{
			name: "proof config",
			mutate: func(t *testing.T, doc *VerifiableDoc) {
				const created = "2023-02-24T23:36:38Z"
				updated := bytes.Replace(doc.rawProofOptions, []byte(created), []byte("2024-02-24T23:36:38Z"), 1)
				if bytes.Equal(updated, doc.rawProofOptions) {
					t.Fatalf("proof config has no %s to tamper", created)
				}
				doc.rawProofOptions = updated
			},
		},
		{
			name: "signature",
			mutate: func(_ *testing.T, doc *VerifiableDoc) {
				doc.Proof.ProofValue[0] ^= 0x01
			},
		},
		{
			name:    "signature length",
			wantErr: "wrong signature size",
			mutate: func(_ *testing.T, doc *VerifiableDoc) {
				doc.Proof.ProofValue = doc.Proof.ProofValue[:len(doc.Proof.ProofValue)-1]
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc := mustParseCredential(t, exEd25519Credential)
			tt.mutate(t, &doc)
			assertVerifyFailed(t, doc, verifier, tt.wantErr)
		})
	}
}

func TestVerify_RejectsVerifierSuiteMismatch(t *testing.T) {
	const ecdsaP256Key = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
	tests := []struct {
		name string
		doc  string
		key  string
	}{
		{name: "eddsa document", doc: exEd25519Credential, key: ecdsaP256Key},
		{name: "ecdsa document", doc: exFullCredential, key: exEd25519PublicKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doc := mustParseCredential(t, tt.doc)
			assertVerifyFailed(t, doc, mustVerifier(t, tt.key), "does not match")
		})
	}
}

func TestGetHash_UnsupportedCryptoSuite(t *testing.T) {
	doc := mustParseCredential(t, ExampleDoc)
	if doc.Proof.CryptoSuite != CryptoSuite_EDDSA_RDFC_2022 {
		t.Fatalf("cryptosuite = %s, want eddsa-rdfc-2022", doc.Proof.CryptoSuite)
	}

	_, err := doc.GetHash(sha256hash)
	if err == nil {
		t.Fatal("GetHash succeeded")
	}
	if !strings.Contains(err.Error(), "Unsupported hashing") {
		t.Fatalf("error = %q, want an unsupported hashing error", err)
	}
}

func TestVerify_UnsupportedCryptoSuite(t *testing.T) {
	doc := mustParseCredential(t, ExampleDoc)
	assertVerifyFailed(t, doc, mustVerifier(t, exEd25519PublicKey), "Unsupported hashing")
}

func mustParseCredential(t *testing.T, document string) VerifiableDoc {
	t.Helper()
	doc, err := ParseDoc([]byte(document))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	return doc
}

func mustVerifier(t *testing.T, multikey string) SigVerifier {
	t.Helper()
	verifier, err := VerifierFromMultikey(multikey)
	if err != nil {
		t.Fatalf("VerifierFromMultikey: %v", err)
	}
	return verifier
}

// wantErr empty means the signature check failed with no error.
// Otherwise the error text must contain wantErr, and the result must be false.
func assertVerifyFailed(t *testing.T, doc VerifiableDoc, verifier SigVerifier, wantErr string) {
	t.Helper()
	ok, err := doc.Verify(verifier)
	if ok {
		t.Fatal("Verify returned true")
	}
	if wantErr == "" {
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("Verify returned no error")
	}
	if !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("error = %q, want substring %q", err, wantErr)
	}
}

func TestParseVerifDoc(t *testing.T) {
	doc, err := ParseDoc([]byte(exFullCredential))
	if err != nil {
		t.Errorf("Error parsing verif doc: %s", err)
		return
	}

	bodyJCS, err := jcs.Transform(doc.Body)
	if err != nil {
		t.Errorf("Error canonicalizing body: %s", err)
	} else if string(bodyJCS) != exCredentialJCSCanon {
		t.Errorf("Body does not match expected:\nGot %s\nExpected %s", string(bodyJCS), exCredentialJCSCanon)
	}

	proofJCS, err := jcs.Transform(doc.rawProofOptions)
	if err != nil {
		t.Errorf("Error canonicalizing proof: %s", err)
	} else if string(proofJCS) != exProofJCSCanon {
		t.Errorf("Proof does not match expected:\nGot %s\nExpected %s", string(proofJCS), exProofJCSCanon)
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
	var body map[string]json.RawMessage
	if err := json.Unmarshal(doc.Body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	got, ok := body["credentialSubject"]
	if !ok {
		t.Fatal("credentialSubject was dropped")
	}
	const want = `"{not: valid}"`
	if string(got) != want {
		t.Errorf("credentialSubject = %s, want %s", got, want)
	}
	if _, ok := body["proof"]; ok {
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
		{
			name:  "proof value",
			proof: `{"type":"DataIntegrityProof","proofPurpose":"assertionMethod","cryptosuite":"eddsa-jcs-2022","proofValue":"not-valid"}`,
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

func TestMakeVerifDoc(t *testing.T) {
	baseDoc := struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}{
		ID:   101,
		Name: "Alice",
	}
	const didString = "did:web:example.com:user:101#key-1"
	didUrl := did.MustParseDIDURL(didString)
	vd, err := MakeVerifiableDoc(baseDoc, CryptoSuite_ECDSA_JCS_2019, &didUrl)
	if err != nil {
		t.Fatalf("Error making verifiable doc: %s", err)
	}
	if vd.Proof.ProofType != "DataIntegrityProof" {
		t.Errorf("Proof type does not match expected, got %s, want %s", vd.Proof.ProofType, "DataIntegrityProof")
	}
	if vd.Proof.ProofPurpose != "assertionMethod" {
		t.Errorf("Proof purpose does not match expected, got %s, want %s", vd.Proof.ProofPurpose, "assertionMethod")
	}
	if vd.Proof.CryptoSuite != CryptoSuite_ECDSA_JCS_2019 {
		t.Errorf("Crypto suite does not match expected, got %s, want %s", vd.Proof.CryptoSuite, "CryptoSuite_ECDSA_JCS_2019")
	}
	if vd.Proof.VerificationMethod.String() != didString {
		t.Errorf("Verification method does not match expected, got %s, want %s", vd.Proof.VerificationMethod, didString)
	}
	expBodyJCS, _ := jcs.Transform([]byte(`{"id":101,"name": "Alice"}`))
	resBodyJCS, _ := jcs.Transform(vd.Body)
	if string(resBodyJCS) != string(expBodyJCS) {
		t.Errorf("Body doe not match expected.\nGot: %s\nExp: %s", string(resBodyJCS), string(expBodyJCS))
	}
}

func TestSignVerifDoc(t *testing.T) {
	baseDoc := struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}{
		ID:   101,
		Name: "Alice",
	}
	const didString = "did:web:example.com:user:101#key-1"
	didUrl := did.MustParseDIDURL(didString)
	vd, err := MakeVerifiableDoc(baseDoc, CryptoSuite_ECDSA_JCS_2019, &didUrl)
	if err != nil {
		t.Fatalf("Error making verifiable doc: %s", err)
	}
	signer, err := GenerateECDSASigner(elliptic.P256())
	if err != nil {
		t.Fatalf("Error generating ECDSA signer: %s", err)
	}
	signedDoc, err := vd.Sign(signer)
	if err != nil {
		t.Fatalf("Error signing verifiable doc: %s", err)
	}

	vd2, err := ParseDoc(signedDoc)
	if err != nil {
		t.Fatalf("Error parsing signed doc: %s", err)
	}
	b, err := vd2.Verify(signer.verifier())
	if err != nil {
		t.Errorf("Error verifying signed doc: %s", err)
	}
	if !b {
		t.Error("Signed doc failed to verify.")
	}
}

// Make's only error is json.Marshal of the document. These are the values
// that call can refuse: unsupported types, non-finite floats, cycles,
// a MarshalJSON method that returns an error, and raw JSON that is not valid.
func TestMake_RejectsUnmarshalableDoc(t *testing.T) {
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
		{name: "-Inf", doc: math.Inf(-1), want: "unsupported value: -Inf"},
		{name: "cycle", doc: loop, want: "encountered a cycle"},
		{name: "marshal error", doc: refuseJSON{}, want: "refuse to marshal"},
		{name: "truncated raw json", doc: json.RawMessage(`{"id":`), want: "unexpected end of JSON input"},
		{name: "trailing junk", doc: json.RawMessage(`{"id":1}x`), want: "invalid character"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			requireMakeError(t, tt.doc, tt.want)
		})
	}
}

// Sign rejects a signer whose signature type does not match the cryptosuite.
// An unknown suite matches neither ECDSA nor EdDSA.
func TestSign_RejectsSuiteMismatch(t *testing.T) {
	ecdsaSigner := mustECDSASigner(t)
	tests := []struct {
		name   string
		suite  CryptoSuiteType
		signer Signer
		want   string
	}{
		{
			name:   "ecdsa signer with eddsa-jcs-2022",
			suite:  CryptoSuite_EDDSA_JCS_2022,
			signer: ecdsaSigner,
			want:   "SigType_ECDSA does not match cryptosuite eddsa-jcs-2022",
		},
		{
			name:   "ecdsa signer with eddsa-rdfc-2022",
			suite:  CryptoSuite_EDDSA_RDFC_2022,
			signer: ecdsaSigner,
			want:   "SigType_ECDSA does not match cryptosuite eddsa-rdfc-2022",
		},
		{
			name:   "ecdsa signer with unknown suite",
			suite:  CryptoSuite_Unknown,
			signer: ecdsaSigner,
			want:   "SigType_ECDSA does not match cryptosuite Unknown crypto suite",
		},
		{
			name:   "eddsa signer with ecdsa-jcs-2019",
			suite:  CryptoSuite_ECDSA_JCS_2019,
			signer: stubSigner{kind: SigType_EDDSA},
			want:   "SigType_EDDSA does not match cryptosuite ecdsa-jcs-2019",
		},
		{
			name:   "eddsa signer with ecdsa-rdfc-2019",
			suite:  CryptoSuite_ECDSA_RDFC_2019,
			signer: stubSigner{kind: SigType_EDDSA},
			want:   "SigType_EDDSA does not match cryptosuite ecdsa-rdfc-2019",
		},
		{
			name:   "unknown signer type",
			suite:  CryptoSuite_ECDSA_JCS_2019,
			signer: stubSigner{kind: SigType(99)},
			want:   "Unknown verifier type does not match cryptosuite ecdsa-jcs-2019",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), tt.suite)
			requireSignError(t, &vd, tt.signer, tt.want)
		})
	}
}

// RDFC suites use the same signature type as the matching JCS suite, so the
// signer check passes. Hashing for RDFC is unsupported, and Sign fails there.
func TestSign_UnsupportedCryptoSuite(t *testing.T) {
	tests := []struct {
		name   string
		suite  CryptoSuiteType
		signer Signer
		want   string
	}{
		{
			name:   "ecdsa-rdfc-2019",
			suite:  CryptoSuite_ECDSA_RDFC_2019,
			signer: mustECDSASigner(t),
			want:   "Error hashing doc: Unsupported hashing for cryptosuite ecdsa-rdfc-2019",
		},
		{
			name:   "eddsa-rdfc-2022",
			suite:  CryptoSuite_EDDSA_RDFC_2022,
			signer: stubSigner{kind: SigType_EDDSA},
			want:   "Error hashing doc: Unsupported hashing for cryptosuite eddsa-rdfc-2022",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), tt.suite)
			requireSignError(t, &vd, tt.signer, tt.want)
		})
	}
}

// Make marshals any JSON value. Sign then needs an object so it can embed the proof.
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
		{name: "number", doc: 101, want: "json: cannot unmarshal number"},
		{name: "string", doc: "Alice", want: "json: cannot unmarshal string"},
		{name: "bool", doc: true, want: "json: cannot unmarshal bool"},
		{name: "array", doc: []int{1, 2}, want: "json: cannot unmarshal array"},
		{name: "empty array", doc: []int{}, want: "json: cannot unmarshal array"},
		{name: "raw array", doc: json.RawMessage(`[1,2]`), want: "json: cannot unmarshal array"},
		{name: "raw string", doc: json.RawMessage(`"Alice"`), want: "json: cannot unmarshal string"},
		{name: "raw null", doc: json.RawMessage(`null`), want: "document is null"},
	}
	signer := mustECDSASigner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, tt.doc, CryptoSuite_ECDSA_JCS_2019)
			requireSignError(t, &vd, signer, "Error parsing base doc: "+tt.want)
		})
	}
}

// encoding/json accepts some documents that JCS canonicalization rejects.
// Make therefore succeeds, and Sign fails while hashing.
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
			vd := mustMakeVerifiableDoc(t, json.RawMessage(tt.raw), CryptoSuite_ECDSA_JCS_2019)
			requireSignError(t, &vd, signer, "Error hashing doc: "+tt.want)
		})
	}
}

// A body that is not JSON fails in GetHash, before a signature is produced.
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
	vm := did.MustParseDIDURL("did:web:example.com:user:101#key-1")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := VerifiableDoc{
				Body: tt.body,
				Proof: Proof{
					ProofType:          "DataIntegrityProof",
					ProofPurpose:       "assertionMethod",
					CryptoSuite:        CryptoSuite_ECDSA_JCS_2019,
					VerificationMethod: &vm,
					Created:            time.Date(2026, 3, 28, 15, 40, 0, 0, time.UTC),
				},
			}
			requireSignError(t, &vd, signer, "Error hashing doc: "+tt.want)
		})
	}
}

// An ECDSA key whose scalar is zero, negative, or larger than the curve order
// cannot sign. A signer that returns its own error is reported the same way.
func TestSign_InvalidSigner(t *testing.T) {
	tests := []struct {
		name   string
		signer func(t *testing.T) Signer
		want   string
	}{
		{
			name: "zero scalar",
			signer: func(t *testing.T) Signer {
				signer := mustECDSASigner(t)
				signer.signKey.D = big.NewInt(0)
				return signer
			},
			want: "Error signing doc: Error signing: ecdsa: private key scalar is zero or negative",
		},
		{
			name: "negative scalar",
			signer: func(t *testing.T) Signer {
				signer := mustECDSASigner(t)
				signer.signKey.D = big.NewInt(-1)
				return signer
			},
			want: "Error signing doc: Error signing: ecdsa: private key scalar is zero or negative",
		},
		{
			name: "scalar too large",
			signer: func(t *testing.T) Signer {
				signer := mustECDSASigner(t)
				signer.signKey.D = new(big.Int).Lsh(big.NewInt(1), 256)
				return signer
			},
			want: "Error signing doc: Error signing: ecdsa: private key scalar too large",
		},
		{
			name: "sign error",
			signer: func(*testing.T) Signer {
				return stubSigner{kind: SigType_ECDSA, signErr: errors.New("key unavailable")}
			},
			want: "Error signing doc: key unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vd := mustMakeVerifiableDoc(t, sampleDoc(), CryptoSuite_ECDSA_JCS_2019)
			requireSignError(t, &vd, tt.signer(t), tt.want)
		})
	}
}

func sampleDoc() map[string]any {
	return map[string]any{"id": 101, "name": "Alice"}
}

func mustMakeVerifiableDoc(t *testing.T, doc any, cs CryptoSuiteType) VerifiableDoc {
	t.Helper()
	vm := did.MustParseDIDURL("did:web:example.com:user:101#key-1")
	vd, err := MakeVerifiableDoc(doc, cs, &vm)
	if err != nil {
		t.Fatalf("Make: %v", err)
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

func requireMakeError(t *testing.T, doc any, want string) {
	t.Helper()
	vm := did.MustParseDIDURL("did:web:example.com:user:101#key-1")
	vd, err := MakeVerifiableDoc(doc, CryptoSuite_ECDSA_JCS_2019, &vm)
	if err == nil {
		t.Fatal("Make succeeded")
	}
	if vd.Body != nil || vd.Proof.ProofType != "" {
		t.Fatalf("Make returned a partial doc on error: body %s type %q", vd.Body, vd.Proof.ProofType)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}

func requireSignError(t *testing.T, vd *VerifiableDoc, signer Signer, want string) {
	t.Helper()
	signed, err := vd.Sign(signer)
	if err == nil {
		t.Fatalf("Sign succeeded: %s", signed)
	}
	if len(signed) != 0 {
		t.Fatalf("Sign returned %q with error %v", signed, err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err, want)
	}
}

// refuseJSON is a document whose MarshalJSON method fails.
type refuseJSON struct{}

func (refuseJSON) MarshalJSON() ([]byte, error) {
	return nil, errors.New("refuse to marshal")
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

func (s stubSigner) sigType() SigType { return s.kind }

func (s stubSigner) hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (s stubSigner) verifier() SigVerifier { return nil }

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
