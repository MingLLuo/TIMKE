package kem

import (
	"fmt"
	"sync"
)

var kemRegistry = &Registry{
	kems: make(map[string]func() KEM),
}

type Registry struct {
	mu   sync.RWMutex
	kems map[string]func() KEM
}

func (r *Registry) Register(name string, constructor func() KEM) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kems[name] = constructor
}

func (r *Registry) Get(name string) (KEM, error) {
	r.mu.RLock()
	constructor, ok := r.kems[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("KEM implementation %s not found", name)
	}

	return constructor(), nil
}

func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name := range r.kems {
		names = append(names, name)
	}

	return names
}

func RegisterKEM(name string, constructor func() KEM) {
	kemRegistry.Register(name, constructor)
}

func GetKEM(name string) (KEM, error) {
	return kemRegistry.Get(name)
}

func ListKEMs() []string {
	return kemRegistry.List()
}

func init() {
	RegisterKEM("OWChCCA-16", func() KEM {
		kem, _ := NewOwChCCAKEM(Security16Type)
		return kem
	})
	RegisterKEM("OWChCCA-32", func() KEM {
		kem, _ := NewOwChCCAKEM(Security32Type)
		return kem
	})

	RegisterKEM("OWChCCA-64", func() KEM {
		kem, _ := NewOwChCCAKEM(Security64Type)
		return kem
	})

	//RegisterKEM("P256-HKDF-SHA256", func() KEM {
	//	kem, _ := NewCirclKEM(P256HKDFSHA256Type)
	//	return kem
	//})
	//RegisterKEM("P384-HKDF-SHA384", func() KEM {
	//	kem, _ := NewCirclKEM(P384HKDFSHA384Type)
	//	return kem
	//})
	//RegisterKEM("P521-HKDF-SHA512", func() KEM {
	//	kem, _ := NewCirclKEM(P521HKDFSHA512Type)
	//	return kem
	//})
	//RegisterKEM("X25519-HKDF-SHA256", func() KEM {
	//	kem, _ := NewCirclKEM(X25519HKDFSHA256Type)
	//	return kem
	//})
	//RegisterKEM("X448-HKDF-SHA512", func() KEM {
	//	kem, _ := NewCirclKEM(X448HKDFSHA512Type)
	//	return kem
	//})
	//
	//RegisterKEM("Kyber512", func() KEM {
	//	kem, _ := NewCirclKEM(Kyber512Type)
	//	return kem
	//})
	//RegisterKEM("Kyber768", func() KEM {
	//	kem, _ := NewCirclKEM(Kyber768Type)
	//	return kem
	//})
	//RegisterKEM("Kyber1024", func() KEM {
	//	kem, _ := NewCirclKEM(Kyber1024Type)
	//	return kem
	//})
	//
	RegisterKEM("ML-KEM-512", func() KEM {
		kem, _ := NewCirclKEM(MLKEM512Type)
		return kem
	})
	RegisterKEM("ML-KEM-768", func() KEM {
		kem, _ := NewCirclKEM(MLKEM768Type)
		return kem
	})
	RegisterKEM("ML-KEM-1024", func() KEM {
		kem, _ := NewCirclKEM(MLKEM1024Type)
		return kem
	})

	//RegisterKEM("Kyber512-X25519", func() KEM {
	//	kem, _ := NewCirclKEM(Kyber512X25519Type)
	//	return kem
	//})
	//RegisterKEM("Kyber768-X25519", func() KEM {
	//	kem, _ := NewCirclKEM(Kyber768X25519Type)
	//	return kem
	//})
	//RegisterKEM("X25519-ML-KEM-768", func() KEM {
	//	kem, _ := NewCirclKEM(MLKEM768X25519Type)
	//	return kem
	//})
	//RegisterKEM("X-Wing", func() KEM {
	//	kem, _ := NewCirclKEM(XWingType)
	//	return kem
	//})
}
