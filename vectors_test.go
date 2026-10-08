package verifdocs

import (
	"encoding/json"
	"strings"
	"testing"
)

// W3C test vectors for the JCS cryptosuites:
//   - ecdsa-jcs-2019 with P-256 and P-384, from
//     https://w3c.github.io/vc-di-ecdsa/#representation-ecdsa-jcs-2019-with-curve-p-256
//     and the P-384 section that follows it.
//   - eddsa-jcs-2022, from Appendix B.3 of
//     https://w3c.github.io/vc-di-eddsa/#representation-eddsa-jcs-2022
//
// All of them sign w3cCredential. As those specifications require, each proof
// carries a copy of the credential's @context, which ParseDoc rejects.

// w3cCredential is the unsigned credential that every vector signs.
const w3cCredential = `{
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

// w3cVector is one signed example from a cryptosuite specification.
type w3cVector struct {
	name      string
	publicKey string // Multikey
	// hashData is the hex hash of the canonical proof options followed by
	// the hash of the canonical credential: the data that is signed.
	hashData  string
	signature string // hex; the decoded proofValue
	proof     string // the proof as published, with its proofValue
}

// signed returns the credential with the vector's proof embedded.
func (v w3cVector) signed() string {
	return strings.TrimSuffix(w3cCredential, "}") + `,"proof":` + v.proof + "}"
}

var vectorP256 = w3cVector{
	name:      "ecdsa-jcs-2019 P-256",
	publicKey: "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
	hashData: "fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a9312648ec25" +
		"59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
	signature: "f15c3b599eb9b3cad05df9d8e8b39a70a86375833b53743c764ac0a88c4457d6" +
		"0707fd7d073e03d906130631d87803f80a9824dc9939632ba92d418181be9d16",
	proof: `{
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
  }`,
}

var vectorP384 = w3cVector{
	name:      "ecdsa-jcs-2019 P-384",
	publicKey: "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
	hashData: "83e5057817abb0c6872eafeaba1a9e53893c58eeb7414fb6d8aa3fa8c7917f7a" +
		"d4792890b257c598baa17f4fbe6d183c" +
		"3e0be671cc1881035d463158c80921973dab3534d4f8dfacf4ff2725a4115eb7" +
		"18e49d66de0e90e7365cd6062abf2259",
	signature: "8b7462ce62db0c8ff19878c4b3561c49eb71b4a743086b6d5b0eda70ecf0afc5" +
		"a03fd88eb207d66b262ed87fd200a4e8e62716e0b329c032b67726b4b0fc737a" +
		"44c1cefdba2fdccb3ece74cc5845aaa93374455a726f6ee4f5f30da9427f608a",
	proof: `{
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
  }`,
}

var vectorEd25519 = w3cVector{
	name:      "eddsa-jcs-2022",
	publicKey: "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
	hashData: "66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db" +
		"59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19",
	signature: "407cd12654b33d718ecbb99179a1506daaa849450bf3fc523cce3e1c96f8b803" +
		"51da3f253d725c6f00b07c9e5448d50b3ef78012b9ab54255116d069c6dd2808",
	proof: `{
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
  }`,
}

var w3cVectors = []w3cVector{vectorP256, vectorP384, vectorEd25519}

// vectorDoc splits a vector's signed credential into a SignedDoc the way
// ParseDoc does, but without ParseDoc's checks. ParseDoc rejects the vectors
// because their proofs carry an @context, and this lets them still test
// hashing and verification.
func vectorDoc(t *testing.T, v w3cVector) SignedDoc {
	t.Helper()
	var document map[string]json.RawMessage
	mustUnmarshal(t, []byte(v.signed()), &document)
	rawProof := document["proof"]
	delete(document, "proof")

	var proof Proof
	mustUnmarshal(t, rawProof, &proof)
	var options map[string]json.RawMessage
	mustUnmarshal(t, rawProof, &options)
	delete(options, "proofValue")

	return SignedDoc{Raw: []byte(v.signed()), Body: mustMarshal(t, document), RawProofOptions: mustMarshal(t, options), Proof: proof}
}
