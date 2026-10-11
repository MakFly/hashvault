package envelope

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// maxRecordJSONSize bounds the stored form: base64 of the largest ciphertext
// plus the wrapped key and the field names.
const maxRecordJSONSize = (maxCiphertextLength+MaxWrappedKeySize+NonceSize)*4/3 + 1024

// ParseRecord decodes a stored record. Unknown fields, trailing data and an
// invalid layout are refused, so a record that parses is one Open can try.
func ParseRecord(data []byte) (Record, error) {
	if len(data) > maxRecordJSONSize {
		return Record{}, fmt.Errorf("%w: encoded record too large", ErrInvalidRecord)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	if dec.More() {
		return Record{}, fmt.Errorf("%w: trailing data", ErrInvalidRecord)
	}
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// MarshalRecord encodes a valid record. Field order is fixed by the struct,
// so the same record always encodes to the same bytes.
func MarshalRecord(r Record) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}
