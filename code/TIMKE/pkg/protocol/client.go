package protocol

import (
	"errors"
	"fmt"
	"io"

	"TIMKE/pkg/crypto"
	"TIMKE/pkg/kem"
)

type Client struct {
	config  *Config
	state   SessionState
	options *SessionOptions
	rand    io.Reader

	ephemeralPublicKey  kem.PublicKey
	ephemeralPrivateKey kem.PrivateKey
	ciphertext1         []byte
	sharedSecret1       []byte // K_1
	tempKey             []byte // K_tmp
	ciphertext2         []byte
	sharedSecret2       []byte // K_2
	sessionKey          []byte // K_main
}

func NewClient(config *Config, options *SessionOptions) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if options == nil || options.ServerPublicKey == nil {
		return nil, errors.New("server public key is required")
	}

	return &Client{
		config:  config,
		state:   StateInitial,
		options: options,
		rand:    kem.DefaultRand,
	}, nil
}

func (c *Client) GenerateClientHello(zeroRTTData []byte) (*ClientHello, error) {
	if c.state != StateInitial {
		return nil, errors.New("client not in initial state")
	}

	// 1. Generate (epk, esk)
	params := c.config.KEM2.Setup()
	epk, esk, err := c.config.KEM2.GenerateKeyPair(params, c.rand)
	if err != nil {
		c.state = StateFailed
		return nil, fmt.Errorf("failed to generate ephemeral key pair: %w", err)
	}
	c.ephemeralPublicKey = epk
	c.ephemeralPrivateKey = esk

	// 2. Use server's long-term public key to encapsulate KEM1
	c.ciphertext1, c.sharedSecret1, err = c.config.KEM1.Encapsulate(c.options.ServerPublicKey, c.rand)
	if err != nil {
		c.state = StateFailed
		return nil, fmt.Errorf("failed to encapsulate KEM1: %w", err)
	}

	// 3. K_tmp = H1(server_pk, C₁, K_1)
	c.tempKey, err = crypto.H1(
		c.options.ServerPublicKey.Bytes(),
		c.ciphertext1,
		c.sharedSecret1,
	)
	if err != nil {
		c.state = StateFailed
		return nil, fmt.Errorf("failed to derive temp key: %w", err)
	}

	// 4. Encrypt 0-RTT data by K_tmp
	var encryptedPayload []byte
	if zeroRTTData != nil {
		encryptedPayload, err = c.config.SymmetricEncryption.Encrypt(c.tempKey, zeroRTTData)
		if err != nil {
			c.state = StateFailed
			return nil, fmt.Errorf("failed to encrypt 0-RTT data: %w", err)
		}
	}

	// 5. Construct ClientHello message
	clientHello := &ClientHello{
		EphemeralPublicKey: c.ephemeralPublicKey.Bytes(),
		Ciphertext1:        c.ciphertext1,
		EncryptedPayload:   encryptedPayload,

		KEM1Type: c.config.KEM1.Setup().Name,
		KEM2Type: c.config.KEM2.Setup().Name,
	}

	c.state = StateAwaitingServerResponse
	return clientHello, nil
}

func (c *Client) ProcessServerResponse(response *ServerResponse) ([]byte, error) {
	if c.state != StateAwaitingServerResponse {
		return nil, errors.New("client not waiting for server response")
	}

	if response == nil {
		c.state = StateFailed
		return nil, errors.New("nil server response")
	}

	c.ciphertext2 = response.Ciphertext2
	sharedSecret2, err := c.config.KEM2.Decapsulate(c.ephemeralPrivateKey, c.ciphertext2)
	if err != nil {
		c.state = StateFailed
		return nil, fmt.Errorf("failed to decapsulate KEM2: %w", err)
	}
	c.sharedSecret2 = sharedSecret2

	c.sessionKey, err = crypto.H2(
		c.options.ServerPublicKey.Bytes(),
		c.ephemeralPublicKey.Bytes(),
		c.ciphertext1,
		c.ciphertext2,
		c.sharedSecret1,
		c.sharedSecret2,
	)
	if err != nil {
		c.state = StateFailed
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	if len(response.EncryptedPayload) == 0 {
		c.state = StateEstablished
		return nil, nil
	}

	plaintext, err := c.config.SymmetricEncryption.Decrypt(c.sessionKey, response.EncryptedPayload)
	if err != nil {
		c.state = StateFailed
		return nil, fmt.Errorf("failed to decrypt server payload: %w", err)
	}

	c.state = StateEstablished
	return plaintext, nil
}

func (c *Client) Encrypt(plaintext []byte) ([]byte, error) {
	if c.state != StateEstablished {
		return nil, errors.New("session not established")
	}

	return c.config.SymmetricEncryption.Encrypt(c.sessionKey, plaintext)
}

func (c *Client) Decrypt(ciphertext []byte) ([]byte, error) {
	if c.state != StateEstablished {
		return nil, errors.New("session not established")
	}

	return c.config.SymmetricEncryption.Decrypt(c.sessionKey, ciphertext)
}

func (c *Client) GetSessionKey() []byte {
	if c.state != StateEstablished {
		return nil
	}

	key := make([]byte, len(c.sessionKey))
	copy(key, c.sessionKey)
	return key
}

func (c *Client) State() SessionState {
	return c.state
}

func (c *Client) Reset() {
	c.state = StateInitial
	c.ephemeralPublicKey = nil
	c.ephemeralPrivateKey = nil
	c.ciphertext1 = nil
	c.sharedSecret1 = nil
	c.tempKey = nil
	c.ciphertext2 = nil
	c.sharedSecret2 = nil
	c.sessionKey = nil
}
