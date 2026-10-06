package verifdocs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/multiformats/go-multibase"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
)

// Helper for testing to just create a DID for a new key.
func makeDIDDoc(path string) ([]byte, error) {
	didID, err := did.ParseDID(path)
	if err != nil {
		return nil, fmt.Errorf("Could not parse DID path: %w", err)
	}

	doc := &did.Document{
		Context: []interface{}{did.DIDContextV1URI()},
		ID:      *didID,
	}
	keyID, _ := did.ParseDIDURL(path + "#key-1")
	keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verificationMethod, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, keyPair.Public())
	doc.AddAssertionMethod(verificationMethod)

	didJson, _ := json.MarshalIndent(doc, "", "  ")
	return didJson, nil
}

// Wrapper type to encode/decode to multibase format a byte array.
// Idea is that you can use this in a struct and be able to encode/decode json transparently.
type MultibaseBytes []byte

// Use the multibase decoder to do the unmarshalling of json data.
func (m *MultibaseBytes) UnmarshalJSON(data []byte) error {
	var encodedString string
	if err := json.Unmarshal(data, &encodedString); err != nil {
		return err
	}
	// if empty just return empty
	if len(data) < 1 {
		return nil
	}

	_, decodedBytes, err := multibase.Decode(encodedString)
	if err != nil {
		return fmt.Errorf("failed to decode multibase string: %w", err)
	}

	*m = decodedBytes
	return nil
}

func (m MultibaseBytes) MarshalJSON() ([]byte, error) {
	str, err := multibase.Encode(multibase.Base58BTC, m)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to encode multibase string: %w", err)
	}
	return json.Marshal(str)
}
