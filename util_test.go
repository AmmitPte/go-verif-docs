package verifdocs

import (
	"bytes"
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

func TestMultibaseBytes_Base58BTC(t *testing.T) {
	// Same proofValue decoded in TestParseProof. The leading z is the Base58BTC prefix.
	const encoded = `"z1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"`
	raw := []byte{
		0x00, 0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27,
		0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6, 0xf0, 0xfb,
		0x50, 0xeb, 0xb8, 0x8f, 0x18, 0xc2, 0x9b, 0x7d,
		0x93,
	}

	t.Run("unmarshal", func(t *testing.T) {
		var got MultibaseBytes
		if err := json.Unmarshal([]byte(encoded), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("decoded = %x, want %x", got, raw)
		}
	})

	t.Run("marshal", func(t *testing.T) {
		got, err := json.Marshal(MultibaseBytes(raw))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(got) != encoded {
			t.Fatalf("encoded = %s, want %s", got, encoded)
		}
	})
}
