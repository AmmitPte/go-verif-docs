package verifdocs

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/AmmitPte/go-verif-docs/test"
	"github.com/nuts-foundation/go-did/did"
)

func TestMakeDID(t *testing.T) {
	result, err := makeDIDDoc("did:web:example.org:blah")
	if err != nil {
		t.Errorf("Error producing DID doc: %v", err)
	}
	fmt.Printf("Got result:\n%s\n", string(result))
}

func TestParseDID(t *testing.T) {
	var didDoc did.Document
	if err := json.Unmarshal(test.ReadTestFile("test/did1.json"), &didDoc); err != nil {
		t.Error(err)
		return
	}

	if didDoc.ID.String() != "did:web:example.org:blah" {
		t.Errorf("Doc ID mismatch, got %s expect %s", didDoc.ID.String(), "did:web:example.org:blah")
	}

	if len(didDoc.VerificationMethod) < 1 {
		t.Errorf("Doc has no verification methods")
		return
	}

	vm := didDoc.VerificationMethod[0]
	if vm.ID.String() != "did:web:example.org:blah#key-1" {
		t.Errorf("VM ID mismatch, got %s expect %s", vm.ID.String(), "did:web:example.org:blah#key-1")
	}

	if vm.Type != "JsonWebKey2020" {
		t.Errorf("VM Type mismatch got %s expect %s", vm.Type, "JsonWebKey2020")
	}

	pk, err := vm.JWK()
	if err != nil {
		t.Errorf("Error getting PK for VM: %s", err)
	}

	if err := pk.Validate(); err != nil {
		t.Errorf("Error validating VM PK: %s", err)
	}

	fmt.Println(vm.PublicKeyJwk)
}
