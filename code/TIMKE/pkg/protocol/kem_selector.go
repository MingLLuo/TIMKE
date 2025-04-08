package protocol

import (
	"fmt"

	"TIMKE/pkg/kem"
)

func SelectKEM(kemType string) (kem.KEM, error) {
	if kemType == "" {
		return nil, fmt.Errorf("KEM type not specified")
	}

	k, err := kem.GetKEM(kemType)
	if err != nil {
		return nil, fmt.Errorf("unknown KEM type: %s", kemType)
	}

	return k, nil
}

func DefaultKEM1() kem.KEM {
	k, err := kem.GetKEM("ML-KEM-768")
	if err == nil {
		return k
	}

	k, err = kem.GetKEM("OW-ChCCA")
	if err == nil {
		return k
	}

	k, err = kem.GetKEM("X25519-HKDF-SHA256")
	if err == nil {
		return k
	}

	k, _ = kem.GetKEM("Kyber768")
	return k
}

func DefaultKEM2() kem.KEM {
	k, err := kem.GetKEM("ML-KEM-1024")
	if err == nil {
		return k
	}

	k, err = kem.GetKEM("X25519-ML-KEM-768")
	if err == nil {
		return k
	}

	k, err = kem.GetKEM("X448-HKDF-SHA512")
	if err == nil {
		return k
	}

	k, _ = kem.GetKEM("Kyber1024")
	return k
}
