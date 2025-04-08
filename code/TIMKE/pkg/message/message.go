package message

//
//type ClientHello struct {
//	// EphemeralPublicKey from KEM2
//	EphemeralPublicKey []byte
//	// Ciphertext1 from KEM1
//	Ciphertext1 []byte
//	// EncryptedPayload 0-RTT by K_tmp
//	EncryptedPayload []byte
//	KEM1Type         string
//	KEM2Type         string
//}
//
//type ServerResponse struct {
//	// Ciphertext2 from KEM2
//	Ciphertext2 []byte
//	// EncryptedPayload by K_main
//	EncryptedPayload []byte
//}
//
//type Serializer interface {
//	MarshalClientHello(ch *ClientHello) ([]byte, error)
//	UnmarshalClientHello(data []byte) (*ClientHello, error)
//	MarshalServerResponse(sr *ServerResponse) ([]byte, error)
//	UnmarshalServerResponse(data []byte) (*ServerResponse, error)
//}
//
////
////type DefaultSerializer struct{}
////
////func (s *DefaultSerializer) MarshalClientHello(ch *ClientHello) ([]byte, error) {
////	result := make([]byte, 0)
////
////	epkLen := uint16(len(ch.EphemeralPublicKey))
////	result = append(result, byte(epkLen>>8), byte(epkLen))
////	result = append(result, ch.EphemeralPublicKey...)
////
////	c1Len := uint16(len(ch.Ciphertext1))
////	result = append(result, byte(c1Len>>8), byte(c1Len))
////	result = append(result, ch.Ciphertext1...)
////
////	payloadLen := uint16(len(ch.EncryptedPayload))
////	result = append(result, byte(payloadLen>>8), byte(payloadLen))
////	result = append(result, ch.EncryptedPayload...)
////
////	kem1TypeLen := uint16(len(ch.KEM1Type))
////	result = append(result, byte(kem1TypeLen>>8), byte(kem1TypeLen))
////	result = append(result, []byte(ch.KEM1Type)...)
////
////	kem2TypeLen := uint16(len(ch.KEM2Type))
////	result = append(result, byte(kem2TypeLen>>8), byte(kem2TypeLen))
////	result = append(result, []byte(ch.KEM2Type)...)
////
////	return result, nil
////}
////
////func (s *DefaultSerializer) UnmarshalClientHello(data []byte) (*ClientHello, error) {
////	if len(data) < 5 {
////		return nil, ErrInvalidMessage
////	}
////
////	ch := &ClientHello{}
////	offset := 0
////
////	// Read EphemeralPublicKey
////	epkLen := uint16(data[offset])<<8 | uint16(data[offset+1])
////	offset += 2
////	if len(data) < offset+int(epkLen) {
////		return nil, ErrInvalidMessage
////	}
////	ch.EphemeralPublicKey = make([]byte, epkLen)
////	copy(ch.EphemeralPublicKey, data[offset:offset+int(epkLen)])
////	offset += int(epkLen)
////
////	// Read Ciphertext1
////	if len(data) < offset+2 {
////		return nil, ErrInvalidMessage
////	}
////	c1Len := uint16(data[offset])<<8 | uint16(data[offset+1])
////	offset += 2
////	if len(data) < offset+int(c1Len) {
////		return nil, ErrInvalidMessage
////	}
////	ch.Ciphertext1 = make([]byte, c1Len)
////	copy(ch.Ciphertext1, data[offset:offset+int(c1Len)])
////	offset += int(c1Len)
////
////	// Read EncryptedPayload
////	if len(data) < offset+2 {
////		return nil, ErrInvalidMessage
////	}
////	payloadLen := uint16(data[offset])<<8 | uint16(data[offset+1])
////	offset += 2
////	if len(data) < offset+int(payloadLen) {
////		return nil, ErrInvalidMessage
////	}
////	ch.EncryptedPayload = make([]byte, payloadLen)
////	copy(ch.EncryptedPayload, data[offset:offset+int(payloadLen)])
////	offset += int(payloadLen)
////
////	// Read KEM1Type
////	if len(data) < offset+2 {
////		return nil, ErrInvalidMessage
////	}
////	kem1TypeLen := uint16(data[offset])<<8 | uint16(data[offset+1])
////	offset += 2
////	if len(data) < offset+int(kem1TypeLen) {
////		return nil, ErrInvalidMessage
////	}
////	ch.KEM1Type = string(data[offset : offset+int(kem1TypeLen)])
////	offset += int(kem1TypeLen)
////
////	// Read KEM2Type
////	if len(data) < offset+2 {
////		return nil, ErrInvalidMessage
////	}
////	kem2TypeLen := uint16(data[offset])<<8 | uint16(data[offset+1])
////	offset += 2
////	if len(data) < offset+int(kem2TypeLen) {
////		return nil, ErrInvalidMessage
////	}
////	ch.KEM2Type = string(data[offset : offset+int(kem2TypeLen)])
////
////	return ch, nil
////}
////
////func (s *DefaultSerializer) MarshalServerResponse(sr *ServerResponse) ([]byte, error) {
////	result := make([]byte, 0)
////
////	c2Len := uint16(len(sr.Ciphertext2))
////	result = append(result, byte(c2Len>>8), byte(c2Len))
////	result = append(result, sr.Ciphertext2...)
////
////	payloadLen := uint16(len(sr.EncryptedPayload))
////	result = append(result, byte(payloadLen>>8), byte(payloadLen))
////	result = append(result, sr.EncryptedPayload...)
////
////	return result, nil
////}
////
////func (s *DefaultSerializer) UnmarshalServerResponse(data []byte) (*ServerResponse, error) {
////	if len(data) < 2 {
////		return nil, ErrInvalidMessage
////	}
////
////	sr := &ServerResponse{}
////	offset := 0
////
////	// Read Ciphertext2
////	c2Len := uint16(data[offset])<<8 | uint16(data[offset+1])
////	offset += 2
////	if len(data) < offset+int(c2Len) {
////		return nil, ErrInvalidMessage
////	}
////	sr.Ciphertext2 = make([]byte, c2Len)
////	copy(sr.Ciphertext2, data[offset:offset+int(c2Len)])
////	offset += int(c2Len)
////
////	// Read EncryptedPayload
////	if len(data) < offset+2 {
////		return nil, ErrInvalidMessage
////	}
////	payloadLen := uint16(data[offset])<<8 | uint16(data[offset+1])
////	offset += 2
////	if len(data) < offset+int(payloadLen) {
////		return nil, ErrInvalidMessage
////	}
////	sr.EncryptedPayload = make([]byte, payloadLen)
////	copy(sr.EncryptedPayload, data[offset:offset+int(payloadLen)])
////
////	return sr, nil
////}
////
////var ErrInvalidMessage = NewError("invalid message format")
////
////type Error struct {
////	msg string
////}
////
////func (e *Error) Error() string {
////	return e.msg
////}
//
//func NewError(msg string) *Error {
//	return &Error{msg: msg}
//}
