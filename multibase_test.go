package verifdocs

import (
	"bytes"
	"encoding/json"
	"testing"
)

// exampleProofValueEncoded is a base58btc multibase string, as used for proof
// values; the leading z is the base58btc prefix. exampleProofValue is its
// decoded bytes.
const exampleProofValueEncoded = "z1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

var exampleProofValue = []byte{
	0x00, 0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27,
	0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6, 0xf0, 0xfb,
	0x50, 0xeb, 0xb8, 0x8f, 0x18, 0xc2, 0x9b, 0x7d,
	0x93,
}

func TestMultibaseBytes_RoundTrip(t *testing.T) {
	encoded := `"` + exampleProofValueEncoded + `"`

	var got MultibaseBytes
	if err := json.Unmarshal([]byte(encoded), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(got, exampleProofValue) {
		t.Errorf("decoded = %x, want %x", got, exampleProofValue)
	}

	out, err := json.Marshal(MultibaseBytes(exampleProofValue))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != encoded {
		t.Errorf("encoded = %s, want %s", out, encoded)
	}
}

// JSON null sets MultibaseBytes to nil, as encoding/json does for other slices.
func TestMultibaseBytes_Null(t *testing.T) {
	got := MultibaseBytes{0x01}
	if err := json.Unmarshal([]byte(`null`), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got != nil {
		t.Errorf("value = %x, want nil", got)
	}
}

func TestMultibaseBytes_RejectsInvalid(t *testing.T) {
	for _, input := range []string{`""`, `"not-multibase"`, `5`} {
		t.Run(input, func(t *testing.T) {
			var m MultibaseBytes
			if err := json.Unmarshal([]byte(input), &m); err == nil {
				t.Errorf("Unmarshal succeeded with %x, want an error", m)
			}
		})
	}
}
