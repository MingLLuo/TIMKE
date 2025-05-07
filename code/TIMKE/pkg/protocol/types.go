package protocol

import (
	"TIMKE/pkg/crypto"
	"TIMKE/pkg/kem"
)

type SessionState int

const (
	StateInitial SessionState = iota
	StateAwaitingServerResponse
	StateEstablished
	StateFailed
)

type Config struct {
	KEM1                kem.KEM
	KEM2                kem.KEM
	SymmetricEncryption crypto.SymmetricEncryption
}

func DefaultConfig() *Config {
	kem1, err := kem.NewCirclKEM(kem.MLKEM768Type)
	if err != nil {
		return nil
	}

	kem2, err := kem.NewCirclKEM(kem.MLKEM1024Type)
	if err != nil {
		return nil
	}

	return &Config{
		KEM1:                kem1,
		KEM2:                kem2,
		SymmetricEncryption: crypto.DefaultSymmetricEncryption(),
	}
}

type SessionOptions struct {
	ServerPublicKey  kem.PublicKey
	ServerPrivateKey kem.PrivateKey
}

func NewSessionOptions() *SessionOptions {
	return &SessionOptions{}
}

func (o *SessionOptions) WithServerPublicKey(pk kem.PublicKey) *SessionOptions {
	o.ServerPublicKey = pk
	return o
}

func (o *SessionOptions) WithServerPrivateKey(sk kem.PrivateKey) *SessionOptions {
	o.ServerPrivateKey = sk
	return o
}
