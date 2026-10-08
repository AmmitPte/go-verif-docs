package verifdocs

import (
	"encoding/json"
	"fmt"

	"github.com/multiformats/go-multibase"
)

// MultibaseBytes is a byte slice that is encoded in JSON as a multibase
// string. It decodes any multibase encoding, and always encodes as
// base58btc, the "z" prefix that the Data Integrity cryptosuites use for
// proof values.
type MultibaseBytes []byte

// UnmarshalJSON decodes a multibase string. JSON null sets the value to nil,
// as encoding/json does for other slices.
func (m *MultibaseBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*m = nil
		return nil
	}
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	_, decoded, err := multibase.Decode(encoded)
	if err != nil {
		return fmt.Errorf("decoding multibase: %w", err)
	}
	*m = decoded
	return nil
}

// MarshalJSON encodes the bytes as a base58btc multibase string.
func (m MultibaseBytes) MarshalJSON() ([]byte, error) {
	encoded, err := multibase.Encode(multibase.Base58BTC, m)
	if err != nil {
		return nil, fmt.Errorf("encoding multibase: %w", err)
	}
	return json.Marshal(encoded)
}
