package kem

import (
	"io"

	owchcca "github.com/MingLLuo/OW-ChCCA-KEM"
	internal "github.com/MingLLuo/OW-ChCCA-KEM/pkg"
)

type OwChCCAKEMType int

const (
	Security16Type OwChCCAKEMType = iota
	Security32Type
	Security64Type
)

type OwChCCAKEM struct {
	kemType  OwChCCAKEMType
	params   Parameters
	owParams owchcca.Parameters
}

type OwChCCAPublicKey struct {
	owPk *owchcca.PublicKey
}

type OwChCCAPrivateKey struct {
	owSk *owchcca.PrivateKey
}

// NewOwChCCAKEM creates a new OW-ChCCA KEM adapter
func NewOwChCCAKEM(kemType OwChCCAKEMType) (*OwChCCAKEM, error) {
	var params internal.Parameters
	var err error
	switch kemType {
	case Security16Type:
		params, err = internal.GetParameterSet("OWChCCA-16")
	case Security32Type:
		params, err = internal.GetParameterSet("OWChCCA-32")
	case Security64Type:
		params, err = internal.GetParameterSet("OWChCCA-64")
	default:
		return nil, ErrUnsupportedKEM
	}

	if err != nil {
		return nil, err
	}

	kem := &OwChCCAKEM{
		kemType:  kemType,
		owParams: params,
	}
	kem.params = kem.Setup()

	return kem, nil
}

func (k *OwChCCAKEM) Setup() Parameters {
	return Parameters{
		Name:   k.owParams.Name,
		KeyLen: k.owParams.KeyParams.SharedKeySize,
	}
}

func (k *OwChCCAKEM) GenerateKeyPair(params Parameters, randSource io.Reader) (PublicKey, PrivateKey, error) {
	owPk, owSk, err := owchcca.GenerateKeyPair(k.owParams)
	if err != nil {
		return nil, nil, err
	}

	pk := &OwChCCAPublicKey{owPk: owPk}
	sk := &OwChCCAPrivateKey{owSk: owSk}

	return pk, sk, nil
}

func (k *OwChCCAKEM) Encapsulate(pk PublicKey, randSource io.Reader) ([]byte, []byte, error) {
	owPkWrapper, ok := pk.(*OwChCCAPublicKey)
	if !ok {
		return nil, nil, ErrInvalidPublicKey
	}

	ct, sk, err := owchcca.Encapsulate(owPkWrapper.owPk)
	return ct, sk, err
}

func (k *OwChCCAKEM) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	owSkWrapper, ok := sk.(*OwChCCAPrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}

	return owchcca.Decapsulate(owSkWrapper.owSk, ciphertext)
}

func (k *OwChCCAKEM) PublicKeySize() int {
	kem := owchcca.NewKEM(k.owParams)
	return kem.PublicKeySize()
}

func (k *OwChCCAKEM) PrivateKeySize() int {
	kem := owchcca.NewKEM(k.owParams)
	return kem.PrivateKeySize()
}

func (k *OwChCCAKEM) CiphertextSize() int {
	kem := owchcca.NewKEM(k.owParams)
	return kem.CiphertextSize()
}

func (k *OwChCCAKEM) SharedKeySize() int {
	kem := owchcca.NewKEM(k.owParams)
	return kem.SharedKeySize()
}

func (k *OwChCCAKEM) ParsePublicKey(data []byte) (PublicKey, error) {
	owPk, err := owchcca.ParsePublicKey(data, &k.owParams)
	if err != nil {
		return nil, err
	}

	return &OwChCCAPublicKey{owPk: owPk}, nil
}

func (k *OwChCCAKEM) ParsePrivateKey(data []byte) (PrivateKey, error) {
	owPkEmpty := owchcca.PublicKey{
		Params: k.owParams,
	}
	owSk, err := owchcca.ParsePrivateKey(data, &owPkEmpty)
	if err != nil {
		return nil, err
	}

	return &OwChCCAPrivateKey{owSk: owSk}, nil
}

func (pk *OwChCCAPublicKey) Bytes() []byte {
	bytes, _ := pk.owPk.Bytes()
	return bytes
}

func (pk *OwChCCAPublicKey) Algorithm() string {
	return pk.owPk.Parameters().Name
}

func (sk *OwChCCAPrivateKey) Bytes() []byte {
	bytes, _ := sk.owSk.Bytes()
	return bytes
}

func (sk *OwChCCAPrivateKey) Algorithm() string {
	return sk.owSk.Public().Parameters().Name
}

func (sk *OwChCCAPrivateKey) PublicKey() PublicKey {
	return &OwChCCAPublicKey{owPk: sk.owSk.Public()}
}
