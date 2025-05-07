package kem

import (
	cryptoRand "crypto/rand"
	"errors"
	"io"
)

type Parameters struct {
	Name   string
	KeyLen int
}

type PublicKey interface {
	Bytes() []byte
	Algorithm() string
}

type PrivateKey interface {
	Bytes() []byte
	Algorithm() string
	PublicKey() PublicKey
}

type KEM interface {
	Setup() Parameters

	GenerateKeyPair(params Parameters, rand io.Reader) (PublicKey, PrivateKey, error)

	Encapsulate(pk PublicKey, rand io.Reader) (ciphertext []byte, sharedSecret []byte, err error)

	Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error)

	ParsePublicKey(data []byte) (PublicKey, error)

	ParsePrivateKey(data []byte) (PrivateKey, error)
}

var DefaultRand = cryptoRand.Reader

var (
	ErrorKEM = errors.New("kem error")

	ErrInvalidPublicKey = errors.New("invalid public key")

	ErrInvalidPrivateKey = errors.New("invalid private key")

	ErrUnsupportedKEM = errors.New("unsupported KEM type")
)
