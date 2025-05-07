package protocol

import (
	"errors"
	"fmt"
	"io"

	"TIMKE/pkg/crypto"
	"TIMKE/pkg/kem"
)

type Server struct {
	config  *Config
	state   SessionState
	options *SessionOptions
	rand    io.Reader

	ephemeralClientPubKey kem.PublicKey
	ciphertext1           []byte
	sharedSecret1         []byte // K_1
	tempKey               []byte // K_tmp
	ciphertext2           []byte
	sharedSecret2         []byte // K_2
	sessionKey            []byte // K_main

	dynamicKEM1 kem.KEM
	dynamicKEM2 kem.KEM
}

func NewServer(config *Config, options *SessionOptions) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if options == nil || options.ServerPrivateKey == nil {
		return nil, errors.New("server private key is required")
	}

	return &Server{
		config:  config,
		state:   StateInitial,
		options: options,
		rand:    kem.DefaultRand,
	}, nil
}

func (s *Server) ProcessClientHello(clientHello *ClientHello) ([]byte, error) {
	if s.state != StateInitial {
		return nil, errors.New("server not in initial state")
	}

	if clientHello == nil {
		s.state = StateFailed
		return nil, errors.New("nil client hello")
	}

	var err error
	if clientHello.KEM1Type != "" && clientHello.KEM2Type != "" {
		s.dynamicKEM1, err = SelectKEM(clientHello.KEM1Type)
		if err != nil {
			s.dynamicKEM1 = DefaultKEM1()
		}

		s.dynamicKEM2, err = SelectKEM(clientHello.KEM2Type)
		if err != nil {
			s.dynamicKEM2 = DefaultKEM2()
		}
	} else {
		s.dynamicKEM1 = DefaultKEM1()
		s.dynamicKEM2 = DefaultKEM2()
	}

	// 1. Parse client ephemeral public key(epkc)
	s.ephemeralClientPubKey, err = s.dynamicKEM2.ParsePublicKey(clientHello.EphemeralPublicKey)
	if err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	s.ciphertext1 = clientHello.Ciphertext1

	// 2. Use server's long-term private key to decapsulate KEM1 ciphertext, get K1
	s.sharedSecret1, err = s.dynamicKEM1.Decapsulate(s.options.ServerPrivateKey, s.ciphertext1)
	if err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("failed to decapsulate KEM1: %w", err)
	}

	// 3. temp Key = H1(serverPubKey || ciphertext1 || K1)
	serverPubKey := s.options.ServerPrivateKey.PublicKey()
	s.tempKey, err = crypto.H1(
		serverPubKey.Bytes(),
		s.ciphertext1,
		s.sharedSecret1,
	)
	if err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("failed to derive temp key: %w", err)
	}

	// 4. Decrypt 0-RTT data
	if len(clientHello.EncryptedPayload) == 0 {
		return nil, nil
	}

	zeroRTTData, err := s.config.SymmetricEncryption.Decrypt(s.tempKey, clientHello.EncryptedPayload)
	if err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("failed to decrypt 0-RTT data: %w", err)
	}

	return zeroRTTData, nil
}

func (s *Server) GenerateServerResponse(payload []byte) (*ServerResponse, error) {
	if s.ephemeralClientPubKey == nil || s.sharedSecret1 == nil {
		return nil, errors.New("client hello not processed")
	}

	// 1. Encapsulate KEM2, get ciphertext2 and K2
	var err error
	s.ciphertext2, s.sharedSecret2, err = s.dynamicKEM2.Encapsulate(s.ephemeralClientPubKey, s.rand)
	if err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("failed to encapsulate KEM2: %w", err)
	}

	// 2. Derive session key K_main
	serverPubKey := s.options.ServerPrivateKey.PublicKey()
	s.sessionKey, err = crypto.H2(
		serverPubKey.Bytes(),
		s.ephemeralClientPubKey.Bytes(),
		s.ciphertext1,
		s.ciphertext2,
		s.sharedSecret1,
		s.sharedSecret2,
	)
	if err != nil {
		s.state = StateFailed
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	// 3. Encrypt payload
	var encryptedPayload []byte
	if payload != nil {
		encryptedPayload, err = s.config.SymmetricEncryption.Encrypt(s.sessionKey, payload)
		if err != nil {
			s.state = StateFailed
			return nil, fmt.Errorf("failed to encrypt payload: %w", err)
		}
	}

	// 4. Return server response
	serverResponse := &ServerResponse{
		Ciphertext2:      s.ciphertext2,
		EncryptedPayload: encryptedPayload,
	}

	s.state = StateEstablished
	return serverResponse, nil
}

func (s *Server) Encrypt(plaintext []byte) ([]byte, error) {
	if s.state != StateEstablished {
		return nil, errors.New("session not established")
	}

	return s.config.SymmetricEncryption.Encrypt(s.sessionKey, plaintext)
}

func (s *Server) Decrypt(ciphertext []byte) ([]byte, error) {
	if s.state != StateEstablished {
		return nil, errors.New("session not established")
	}

	return s.config.SymmetricEncryption.Decrypt(s.sessionKey, ciphertext)
}

func (s *Server) GetSessionKey() []byte {
	if s.state != StateEstablished {
		return nil
	}

	key := make([]byte, len(s.sessionKey))
	copy(key, s.sessionKey)
	return key
}

func (s *Server) State() SessionState {
	return s.state
}

func (s *Server) Reset() {
	s.state = StateInitial
	s.ephemeralClientPubKey = nil
	s.ciphertext1 = nil
	s.sharedSecret1 = nil
	s.tempKey = nil
	s.ciphertext2 = nil
	s.sharedSecret2 = nil
	s.sessionKey = nil
	s.dynamicKEM1 = nil
	s.dynamicKEM2 = nil
}
