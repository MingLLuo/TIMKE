package kem

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/kem/xwing"
)

type KEMType int

const (
	// HPKE
	P256HKDFSHA256Type KEMType = iota
	P384HKDFSHA384Type
	P521HKDFSHA512Type
	X25519HKDFSHA256Type
	X448HKDFSHA512Type

	// NIST PQC Round 3
	Kyber512Type
	Kyber768Type
	Kyber1024Type

	// FIPS 203
	MLKEM512Type
	MLKEM768Type
	MLKEM1024Type

	// Hybrid
	Kyber512X25519Type
	Kyber768X25519Type
	MLKEM768X25519Type
	XWingType
)

type CirclKEM struct {
	scheme  kem.Scheme
	kemType KEMType
}

func NewCirclKEM(kemType KEMType) (*CirclKEM, error) {
	var scheme kem.Scheme

	switch kemType {
	case P256HKDFSHA256Type:
		scheme = hpke.KEM_P256_HKDF_SHA256.Scheme()
	case P384HKDFSHA384Type:
		scheme = hpke.KEM_P384_HKDF_SHA384.Scheme()
	case P521HKDFSHA512Type:
		scheme = hpke.KEM_P521_HKDF_SHA512.Scheme()
	case X25519HKDFSHA256Type:
		scheme = hpke.KEM_X25519_HKDF_SHA256.Scheme()
	case X448HKDFSHA512Type:
		scheme = hpke.KEM_X448_HKDF_SHA512.Scheme()
	case Kyber512Type:
		scheme = kyber512.Scheme()
	case Kyber768Type:
		scheme = kyber768.Scheme()
	case Kyber1024Type:
		scheme = kyber1024.Scheme()
	case MLKEM512Type:
		scheme = mlkem512.Scheme()
	case MLKEM768Type:
		scheme = mlkem768.Scheme()
	case MLKEM1024Type:
		scheme = mlkem1024.Scheme()
	case Kyber512X25519Type:
		scheme = hybrid.Kyber512X25519()
	case Kyber768X25519Type:
		scheme = hybrid.Kyber768X25519()
	case MLKEM768X25519Type:
		scheme = hybrid.X25519MLKEM768()
	case XWingType:
		scheme = xwing.Scheme()
	default:
		return nil, fmt.Errorf("unsupported KEM type: %d", kemType)
	}

	return &CirclKEM{
		scheme:  scheme,
		kemType: kemType,
	}, nil
}

func (k *CirclKEM) Setup() Parameters {
	return Parameters{
		Name:   k.scheme.Name(),
		KeyLen: k.scheme.SharedKeySize(),
	}
}

func (k *CirclKEM) GenerateKeyPair(params Parameters, rand io.Reader) (PublicKey, PrivateKey, error) {
	// circl use crypto/rand to generate random numbers internally, we ignore the rand parameter here
	pk, sk, err := k.scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	return &CirclPublicKey{pk: pk, scheme: k.scheme}, &CirclPrivateKey{sk: sk, scheme: k.scheme}, nil
}

func (k *CirclKEM) Encapsulate(pk PublicKey, rand io.Reader) ([]byte, []byte, error) {
	circlPK, ok := pk.(*CirclPublicKey)
	if !ok {
		return nil, nil, errors.New("invalid public key type")
	}

	return k.scheme.Encapsulate(circlPK.pk)
}

func (k *CirclKEM) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	circlSK, ok := sk.(*CirclPrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type")
	}

	return k.scheme.Decapsulate(circlSK.sk, ciphertext)
}

func (k *CirclKEM) ParsePublicKey(data []byte) (PublicKey, error) {
	pk, err := k.scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, err
	}

	return &CirclPublicKey{pk: pk, scheme: k.scheme}, nil
}

func (k *CirclKEM) ParsePrivateKey(data []byte) (PrivateKey, error) {
	sk, err := k.scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, err
	}

	return &CirclPrivateKey{sk: sk, scheme: k.scheme}, nil
}

type CirclPublicKey struct {
	pk     kem.PublicKey
	scheme kem.Scheme
}

func (pk *CirclPublicKey) Bytes() []byte {
	data, _ := pk.pk.MarshalBinary()
	return data
}

func (pk *CirclPublicKey) Algorithm() string {
	return pk.scheme.Name()
}

type CirclPrivateKey struct {
	sk     kem.PrivateKey
	scheme kem.Scheme
}

func (sk *CirclPrivateKey) Bytes() []byte {
	data, _ := sk.sk.MarshalBinary()
	return data
}

func (sk *CirclPrivateKey) Algorithm() string {
	return sk.scheme.Name()
}

func (sk *CirclPrivateKey) PublicKey() PublicKey {
	return &CirclPublicKey{
		pk:     sk.sk.Public(),
		scheme: sk.scheme,
	}
}
