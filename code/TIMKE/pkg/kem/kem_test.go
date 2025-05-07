package kem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestOwChCCAKEM_Setup(t *testing.T) {
	testCases := []struct {
		name    string
		kemType OwChCCAKEMType
	}{
		{"Security16", Security16Type},
		{"Security32", Security32Type},
		{"Security64", Security64Type},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kem, err := NewOwChCCAKEM(tc.kemType)
			if err != nil {
				t.Fatalf("Failed to create KEM: %v", err)
			}

			params := kem.Setup()
			if params.Name == "" {
				t.Error("Expected non-empty parameter name")
			}
			if params.KeyLen <= 0 {
				t.Error("Expected positive key length")
			}

			t.Logf("Parameters: Name=%s, KeyLen=%d", params.Name, params.KeyLen)
		})
	}
}

func TestOwChCCAKEM_InvalidType(t *testing.T) {
	_, err := NewOwChCCAKEM(OwChCCAKEMType(999)) // Invalid type
	if err == nil {
		t.Error("Expected error for invalid KEM type, got nil")
	}
}

func TestOwChCCAKEM_KeyGeneration(t *testing.T) {
	testCases := []struct {
		name    string
		kemType OwChCCAKEMType
	}{
		{"Security16", Security16Type},
		{"Security32", Security32Type},
		{"Security64", Security64Type},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kem, err := NewOwChCCAKEM(tc.kemType)
			if err != nil {
				t.Fatalf("Failed to create KEM: %v", err)
			}

			// Generate key pair
			pk, sk, err := kem.GenerateKeyPair(kem.params, rand.Reader)
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}

			// Verify keys are not nil
			if pk == nil {
				t.Error("Public key is nil")
			}
			if sk == nil {
				t.Error("Private key is nil")
			}

			// Check if the public key from private key matches the original public key
			pkFromSk := sk.PublicKey()
			pkBytes := pk.Bytes()
			pkFromSkBytes := pkFromSk.Bytes()
			if err != nil {
				t.Fatalf("Failed to get public key bytes from private key: %v", err)
			}

			if !bytes.Equal(pkBytes, pkFromSkBytes) {
				t.Error("Public key from private key doesn't match original public key")
			}

			// Check algorithm
			if pk.Algorithm() == "" {
				t.Error("Public key algorithm is empty")
			}
			if sk.Algorithm() == "" {
				t.Error("Private key algorithm is empty")
			}
		})
	}
}

func TestOwChCCAKEM_EncapsulateDecapsulate(t *testing.T) {
	testCases := []struct {
		name    string
		kemType OwChCCAKEMType
	}{
		{"Security16", Security16Type},
		{"Security32", Security32Type},
		//{"Security64", Security64Type},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kem, err := NewOwChCCAKEM(tc.kemType)
			if err != nil {
				t.Fatalf("Failed to create KEM: %v", err)
			}

			// Generate key pair
			pk, sk, err := kem.GenerateKeyPair(kem.params, rand.Reader)
			if err != nil {
				t.Fatalf("Key generation failed: %v", err)
			}

			// Encapsulate
			ct, ss1, err := kem.Encapsulate(pk, rand.Reader)
			if err != nil {
				t.Fatalf("Encapsulation failed: %v", err)
			}
			if len(ct) == 0 {
				t.Error("Ciphertext is empty")
			}
			if len(ss1) == 0 {
				t.Error("Shared secret is empty")
			}

			// Decapsulate
			ss2, err := kem.Decapsulate(sk, ct)
			if err != nil {
				t.Fatalf("Decapsulation failed: %v", err)
			}
			if len(ss2) == 0 {
				t.Error("Decapsulated shared secret is empty")
			}

			// Verify shared secrets match
			if !bytes.Equal(ss1, ss2) {
				t.Errorf("Shared secrets don't match: %v != %v", ss1, ss2)
			}
		})
	}
}

func TestOwChCCAKEM_InvalidInputs(t *testing.T) {
	kem, err := NewOwChCCAKEM(Security16Type)
	if err != nil {
		t.Fatalf("Failed to create KEM: %v", err)
	}

	// Generate a valid key pair
	pk, sk, err := kem.GenerateKeyPair(kem.params, rand.Reader)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	// Create invalid keys
	invalidPk := &mockPublicKey{}
	invalidSk := &mockPrivateKey{}

	// Test encapsulation with invalid public key
	_, _, err = kem.Encapsulate(invalidPk, rand.Reader)
	if err == nil {
		t.Error("Expected error for encapsulation with invalid public key, got nil")
	}

	// Test decapsulation with invalid private key
	_, err = kem.Decapsulate(invalidSk, []byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for decapsulation with invalid private key, got nil")
	}

	// Test decapsulation with invalid ciphertext
	// First create a valid ciphertext
	ct, _, err := kem.Encapsulate(pk, rand.Reader)
	if err != nil {
		t.Fatalf("Encapsulation failed: %v", err)
	}

	// Modify the ciphertext to make it invalid
	if len(ct) > 0 {
		invalidCt := make([]byte, len(ct))
		copy(invalidCt, ct)
		invalidCt[0] ^= 0xFF // Flip bits in the first byte

		// Attempt to decapsulate with invalid ciphertext
		_, err = kem.Decapsulate(sk, invalidCt)
		if err == nil {
			t.Error("Expected error for decapsulation with invalid ciphertext, got nil")
		}
	}
}

func TestOwChCCAKEM_KeySerialization(t *testing.T) {
	kem, err := NewOwChCCAKEM(Security16Type)
	if err != nil {
		t.Fatalf("Failed to create KEM: %v", err)
	}

	pk, sk, err := kem.GenerateKeyPair(kem.params, rand.Reader)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	pkBytes := pk.Bytes()
	if len(pkBytes) == 0 {
		t.Error("Serialized public key is empty")
	}

	parsedPk, err := kem.ParsePublicKey(pkBytes)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	parsedPkBytes := parsedPk.Bytes()
	if !bytes.Equal(pkBytes, parsedPkBytes) {
		t.Error("Parsed public key doesn't match original")
	}

	skBytes := sk.Bytes()
	if len(skBytes) == 0 {
		t.Error("Serialized private key is empty")
	}
}

type mockPublicKey struct{}

func (m *mockPublicKey) Bytes() []byte {
	return []byte("mock public key")
}

func (m *mockPublicKey) Algorithm() string {
	return "mock"
}

type mockPrivateKey struct{}

func (m *mockPrivateKey) Bytes() []byte {
	return []byte("mock private key")
}

func (m *mockPrivateKey) Algorithm() string {
	return "mock"
}

func (m *mockPrivateKey) PublicKey() PublicKey {
	return &mockPublicKey{}
}

func BenchmarkOwChCCAKEM(b *testing.B) {
	kem, err := NewOwChCCAKEM(Security16Type)
	if err != nil {
		b.Fatalf("Failed to create KEM: %v", err)
	}

	pk, sk, err := kem.GenerateKeyPair(kem.params, rand.Reader)
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	b.Run("GenerateKeyPair", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := kem.GenerateKeyPair(kem.params, rand.Reader)
			if err != nil {
				b.Fatalf("Key generation failed: %v", err)
			}
		}
	})

	b.Run("Encapsulate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := kem.Encapsulate(pk, rand.Reader)
			if err != nil {
				b.Fatalf("Encapsulation failed: %v", err)
			}
		}
	})

	ct, _, err := kem.Encapsulate(pk, rand.Reader)
	if err != nil {
		b.Fatalf("Encapsulation failed: %v", err)
	}

	b.Run("Decapsulate", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := kem.Decapsulate(sk, ct)
			if err != nil {
				b.Fatalf("Decapsulation failed: %v", err)
			}
		}
	})
}
