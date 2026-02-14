package protocol

import (
	"encoding/binary"
	"errors"
)

var (
	// ErrInvalidMessage indicates the message format is invalid
	ErrInvalidMessage = errors.New("invalid message format")
	// ErrBufferTooShort indicates the buffer is too short to read the required data
	ErrBufferTooShort = errors.New("buffer too short")
)

// ClientHello represents a client's first message in the protocol
type ClientHello struct {
	EphemeralPublicKey []byte
	Ciphertext1        []byte
	EncryptedPayload   []byte
	KEM1Type           string
	KEM2Type           string
}

// ServerResponse represents a server's response in the protocol
type ServerResponse struct {
	Ciphertext2      []byte
	EncryptedPayload []byte
}

// Serializer defines methods for serializing and deserializing protocol messages
type Serializer interface {
	MarshalClientHello(ch *ClientHello) ([]byte, error)
	UnmarshalClientHello(data []byte) (*ClientHello, error)
	MarshalServerResponse(sr *ServerResponse) ([]byte, error)
	UnmarshalServerResponse(data []byte) (*ServerResponse, error)
}

// DefaultSerializer implements the Serializer interface
type DefaultSerializer struct{}

// readLengthPrefixedBytes reads a length-prefixed byte array from data starting at offset
// returns the bytes and the new offset
func readLengthPrefixedBytes(data []byte, offset int) ([]byte, int, error) {
	// Check if we can read the length (4 bytes)
	if offset+4 > len(data) {
		return nil, offset, ErrBufferTooShort
	}

	// Read the length
	length := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Check if we can read the data
	if offset+int(length) > len(data) {
		return nil, offset, ErrBufferTooShort
	}

	// Extract the data
	result := make([]byte, length)
	copy(result, data[offset:offset+int(length)])
	offset += int(length)

	return result, offset, nil
}

// writeLengthPrefixedBytes appends a length-prefixed byte array to the result
func writeLengthPrefixedBytes(result []byte, data []byte) []byte {
	// Reserve 4 bytes in-place for length to avoid a tiny temporary allocation.
	lengthOffset := len(result)
	result = append(result, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(result[lengthOffset:lengthOffset+4], uint32(len(data)))
	result = append(result, data...)

	return result
}

// MarshalClientHello serializes a ClientHello into a byte slice
func (s *DefaultSerializer) MarshalClientHello(ch *ClientHello) ([]byte, error) {
	if ch == nil {
		return nil, errors.New("cannot marshal nil ClientHello")
	}

	// Pre-allocate a reasonable buffer to reduce allocations
	estimatedSize := 4 + len(ch.EphemeralPublicKey) +
		4 + len(ch.Ciphertext1) +
		4 + len(ch.EncryptedPayload) +
		4 + len(ch.KEM1Type) +
		4 + len(ch.KEM2Type)

	result := make([]byte, 0, estimatedSize)

	result = writeLengthPrefixedBytes(result, ch.EphemeralPublicKey)
	result = writeLengthPrefixedBytes(result, ch.Ciphertext1)
	result = writeLengthPrefixedBytes(result, ch.EncryptedPayload)
	result = writeLengthPrefixedBytes(result, []byte(ch.KEM1Type))
	result = writeLengthPrefixedBytes(result, []byte(ch.KEM2Type))

	return result, nil
}

// UnmarshalClientHello deserializes a byte slice into a ClientHello
func (s *DefaultSerializer) UnmarshalClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 4 {
		return nil, ErrInvalidMessage
	}

	ch := &ClientHello{}
	offset := 0
	var err error

	// Read each field
	ch.EphemeralPublicKey, offset, err = readLengthPrefixedBytes(data, offset)
	if err != nil {
		return nil, err
	}

	ch.Ciphertext1, offset, err = readLengthPrefixedBytes(data, offset)
	if err != nil {
		return nil, err
	}

	ch.EncryptedPayload, offset, err = readLengthPrefixedBytes(data, offset)
	if err != nil {
		return nil, err
	}

	kem1TypeBytes, offset, err := readLengthPrefixedBytes(data, offset)
	if err != nil {
		return nil, err
	}
	ch.KEM1Type = string(kem1TypeBytes)

	kem2TypeBytes, offset, err := readLengthPrefixedBytes(data, offset)
	if err != nil {
		return nil, err
	}
	ch.KEM2Type = string(kem2TypeBytes)

	// Check if we've consumed the entire buffer
	if offset != len(data) {
		return ch, errors.New("extra data after message")
	}

	return ch, nil
}

// MarshalServerResponse serializes a ServerResponse into a byte slice
func (s *DefaultSerializer) MarshalServerResponse(sr *ServerResponse) ([]byte, error) {
	if sr == nil {
		return nil, errors.New("cannot marshal nil ServerResponse")
	}

	// Pre-allocate a reasonable buffer
	estimatedSize := 4 + len(sr.Ciphertext2) + 4 + len(sr.EncryptedPayload)
	result := make([]byte, 0, estimatedSize)

	result = writeLengthPrefixedBytes(result, sr.Ciphertext2)
	result = writeLengthPrefixedBytes(result, sr.EncryptedPayload)

	return result, nil
}

// UnmarshalServerResponse deserializes a byte slice into a ServerResponse
func (s *DefaultSerializer) UnmarshalServerResponse(data []byte) (*ServerResponse, error) {
	if len(data) < 4 {
		return nil, ErrInvalidMessage
	}

	sr := &ServerResponse{}
	offset := 0
	var err error

	// Read each field
	sr.Ciphertext2, offset, err = readLengthPrefixedBytes(data, offset)
	if err != nil {
		return nil, err
	}

	sr.EncryptedPayload, offset, err = readLengthPrefixedBytes(data, offset)
	if err != nil {
		return nil, err
	}

	// Check if we've consumed the entire buffer
	if offset != len(data) {
		return sr, errors.New("extra data after message")
	}

	return sr, nil
}
