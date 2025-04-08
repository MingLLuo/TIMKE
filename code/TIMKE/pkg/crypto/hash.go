package crypto

import (
	"errors"

	"TIMKE/pkg/crypto/sha3"
)

type Hash struct {
	h sha3.State
}

func NewHash() *Hash {
	return &Hash{
		h: sha3.New512(),
	}
}

func (h *Hash) Hash(data ...[]byte) ([]byte, error) {
	h.h.Reset()

	for _, d := range data {
		if _, err := h.h.Write(d); err != nil {
			return nil, err
		}
	}
	return h.h.Sum(nil), nil
}

// H1 K_tmp = H1(pk_S, C_1, K_1)
func H1(pkS, c1, k1 []byte) ([]byte, error) {
	if pkS == nil || c1 == nil || k1 == nil {
		return nil, errors.New("invalid input to H1")
	}

	h := NewHash()
	domain := []byte("TIMKE-H1")
	return h.Hash(domain, pkS, c1, k1)
}

// H2 K_main = H2(pk_S, epk_C, C_1, C_2, K_1, K_2)
func H2(pkS, epkC, c1, c2, k1, k2 []byte) ([]byte, error) {
	if pkS == nil || epkC == nil || c1 == nil || c2 == nil || k1 == nil || k2 == nil {
		return nil, errors.New("invalid input to H2")
	}

	h := NewHash()
	domain := []byte("TIMKE-H2")
	return h.Hash(domain, pkS, epkC, c1, c2, k1, k2)
}
