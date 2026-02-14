package kem

import (
	"io"
	"sort"
	"testing"
)

func TestKEMRegistry(t *testing.T) {
	t.Run("ListKEMs should return all registered KEMs", func(t *testing.T) {
		kems := ListKEMs()
		expected := []string{
			"OWChCCA-16",
			"OWChCCA-32",
			"OWChCCA-64",
			"ML-KEM-512",
			"ML-KEM-768",
			"ML-KEM-1024",
		}

		sort.Strings(kems)
		sort.Strings(expected)

		for _, e := range expected {
			found := false
			for _, k := range kems {
				if e == k {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected KEM %s not found in registry", e)
			}
		}

		t.Logf("Registered KEMs: %v", kems)
	})

	t.Run("GetKEM should return correct implementation", func(t *testing.T) {
		kem1, err := GetKEM("OWChCCA-32")
		if err != nil {
			t.Fatalf("GetKEM failed for OW-ChCCA-KEM: %v", err)
		}
		if kem1.Setup().Name != "OWChCCA-32" {
			t.Errorf("Expected OW-ChCCA-KEM, got %s", kem1.Setup().Name)
		}

		kem2, err := GetKEM("ML-KEM-768")
		if err != nil {
			t.Fatalf("GetKEM failed for ML-KEM-768: %v", err)
		}
		if kem2.Setup().Name != "ML-KEM-768" {
			t.Errorf("Expected ML-KEM-768, got %s", kem2.Setup().Name)
		}

		_, err = GetKEM("NonExistentKEM")
		if err == nil {
			t.Error("Expected error for non-existent KEM, got nil")
		}
	})

	t.Run("RegisterKEM should add new implementation", func(t *testing.T) {
		RegisterKEM("TestKEM", func() KEM {
			return &testKEM{}
		})

		kem, err := GetKEM("TestKEM")
		if err != nil {
			t.Fatalf("GetKEM failed for TestKEM: %v", err)
		}
		if kem.Setup().Name != "TestKEM" {
			t.Errorf("Expected TestKEM, got %s", kem.Setup().Name)
		}

		kems := ListKEMs()
		found := false
		for _, k := range kems {
			if k == "TestKEM" {
				found = true
				break
			}
		}
		if !found {
			t.Error("TestKEM not found in registry after registration")
		}
	})
}

type testKEM struct{}

func (k *testKEM) Setup() Parameters {
	return Parameters{
		Name:   "TestKEM",
		KeyLen: 32,
	}
}

func (k *testKEM) GenerateKeyPair(params Parameters, rand io.Reader) (PublicKey, PrivateKey, error) {
	return &testPublicKey{}, &testPrivateKey{}, nil
}

func (k *testKEM) Encapsulate(pk PublicKey, rand io.Reader) ([]byte, []byte, error) {
	return []byte("ciphertext"), []byte("secret"), nil
}

func (k *testKEM) Decapsulate(sk PrivateKey, ciphertext []byte) ([]byte, error) {
	return []byte("secret"), nil
}

func (k *testKEM) ParsePublicKey(data []byte) (PublicKey, error) {
	return &testPublicKey{}, nil
}

func (k *testKEM) ParsePrivateKey(data []byte) (PrivateKey, error) {
	return &testPrivateKey{}, nil
}

type testPublicKey struct{}

func (pk *testPublicKey) Bytes() []byte {
	return []byte("public key")
}

func (pk *testPublicKey) Algorithm() string {
	return "TestKEM"
}

type testPrivateKey struct{}

func (sk *testPrivateKey) Bytes() []byte {
	return []byte("private key")
}

func (sk *testPrivateKey) Algorithm() string {
	return "TestKEM"
}

func (sk *testPrivateKey) PublicKey() PublicKey {
	return &testPublicKey{}
}
