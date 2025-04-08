package protocol

import (
	"bytes"
	"testing"

	"TIMKE/pkg/kem"
)

func TestProtocolIntegration(t *testing.T) {
	kemCombinations := []struct {
		name string
		kem1 string
		kem2 string
	}{
		{"OWChCCA-16 + OWChCCA-16", "OWChCCA-16", "OWChCCA-16"},
		{"OWChCCA-32 + OWChCCA-16", "OWChCCA-32", "OWChCCA-16"},
		{"ML-KEM-768 + ML-KEM-1024", "ML-KEM-768", "ML-KEM-1024"},
		{"OWChCCA-16 + ML-KEM-1024", "OWChCCA-16", "ML-KEM-1024"},
	}

	for _, kemCombo := range kemCombinations {
		t.Run(kemCombo.name, func(t *testing.T) {
			testProtocolWithKEMs(t, kemCombo.kem1, kemCombo.kem2)
		})
	}
}

func testProtocolWithKEMs(t *testing.T, kem1Name, kem2Name string) {
	kem1, err := kem.GetKEM(kem1Name)
	if err != nil {
		t.Fatalf("Failed to get KEM1 %s: %v", kem1Name, err)
	}

	kem2, err := kem.GetKEM(kem2Name)
	if err != nil {
		t.Fatalf("Failed to get KEM2 %s: %v", kem2Name, err)
	}

	config := &Config{
		KEM1:                kem1,
		KEM2:                kem2,
		SymmetricEncryption: DefaultConfig().SymmetricEncryption,
	}

	serverPubKey, serverPrivKey, err := kem1.GenerateKeyPair(kem1.Setup(), nil)
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	t.Logf("Generated server key pair: %s", serverPubKey.Algorithm())

	clientOptions := NewSessionOptions().WithServerPublicKey(serverPubKey)
	client, err := NewClient(config, clientOptions)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	serverOptions := NewSessionOptions().WithServerPrivateKey(serverPrivKey)
	server, err := NewServer(config, serverOptions)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	t.Log("Created client and server")

	// 1. 客户端生成初始消息
	zeroRTTMessage := []byte("Hello, this is 0-RTT data!")
	clientHello, err := client.GenerateClientHello(zeroRTTMessage)
	if err != nil {
		t.Fatalf("Failed to generate client hello: %v", err)
	}

	if clientHello.KEM1Type != kem1Name {
		t.Errorf("Expected KEM1Type %s, got %s", kem1Name, clientHello.KEM1Type)
	}
	if clientHello.KEM2Type != kem2Name {
		t.Errorf("Expected KEM2Type %s, got %s", kem2Name, clientHello.KEM2Type)
	}

	t.Log("Client generated initial message with 0-RTT data")

	// 2. 序列化客户端初始消息
	serializer := &DefaultSerializer{}
	clientHelloBytes, err := serializer.MarshalClientHello(clientHello)
	if err != nil {
		t.Fatalf("Failed to marshal client hello: %v", err)
	}

	t.Logf("Serialized client hello: %d bytes", len(clientHelloBytes))

	// 3. 服务器解析客户端初始消息
	parsedClientHello, err := serializer.UnmarshalClientHello(clientHelloBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal client hello: %v", err)
	}

	// 4. 服务器处理客户端初始消息
	zeroRTTData, err := server.ProcessClientHello(parsedClientHello)
	if err != nil {
		t.Fatalf("Failed to process client hello: %v", err)
	}

	if !bytes.Equal(zeroRTTMessage, zeroRTTData) {
		t.Errorf("0-RTT data mismatch: expected %q, got %q", zeroRTTMessage, zeroRTTData)
	}

	t.Logf("Server received 0-RTT data: %q", zeroRTTData)

	// 5. 服务器生成响应消息
	serverPayload := []byte("Hello, this is server response!")
	serverResponse, err := server.GenerateServerResponse(serverPayload)
	if err != nil {
		t.Fatalf("Failed to generate server response: %v", err)
	}

	t.Log("Server generated response")

	// 6. 序列化服务器响应消息
	serverResponseBytes, err := serializer.MarshalServerResponse(serverResponse)
	if err != nil {
		t.Fatalf("Failed to marshal server response: %v", err)
	}

	t.Logf("Serialized server response: %d bytes", len(serverResponseBytes))

	// 7. 客户端解析服务器响应消息
	parsedServerResponse, err := serializer.UnmarshalServerResponse(serverResponseBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal server response: %v", err)
	}

	// 8. 客户端处理服务器响应消息
	serverData, err := client.ProcessServerResponse(parsedServerResponse)
	if err != nil {
		t.Fatalf("Failed to process server response: %v", err)
	}

	// 验证服务器数据
	if !bytes.Equal(serverPayload, serverData) {
		t.Errorf("Server data mismatch: expected %q, got %q", serverPayload, serverData)
	}

	t.Logf("Client received server data: %q", serverData)

	// 9. 验证客户端和服务器的会话密钥一致
	clientSessionKey := client.GetSessionKey()
	serverSessionKey := server.GetSessionKey()

	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		t.Error("Client and server session keys do not match")
	} else {
		t.Logf("Session key match: %x", clientSessionKey[:8])
	}

	// 10. 测试加密通信
	testMessage := []byte("Encrypted message for testing")
	encrypted, err := client.Encrypt(testMessage)
	if err != nil {
		t.Fatalf("Client encryption failed: %v", err)
	}

	decrypted, err := server.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Server decryption failed: %v", err)
	}

	if !bytes.Equal(testMessage, decrypted) {
		t.Errorf("Encrypted message mismatch: expected %q, got %q", testMessage, decrypted)
	}

	t.Logf("Successfully tested encrypted communication")
}
