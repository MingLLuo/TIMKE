package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"TIMKE/pkg/kem"
	"TIMKE/pkg/protocol"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
)

func main() {
	var (
		port       = flag.Int("port", 8443, "Port to listen on")
		kem1Type   = flag.String("kem1", "ML-KEM-768", "KEM type for the first stage (OWChCCA-32, ML-KEM-768, etc.)")
		kem2Type   = flag.String("kem2", "ML-KEM-768", "KEM type for the second stage (OWChCCA-32, ML-KEM-768, etc.)")
		keyFile    = flag.String("key", ".temp/server-key.pem", "Path to server private key file (optional)")
		genKeyFile = flag.String("genkey", "", "Generate a new server key pair and save to file (optional)")
		verbose    = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", 0)

	printBanner(logger)

	// List available KEMs
	logger.Printf("%sAvailable KEM algorithms:%s\n", colorYellow, colorReset)
	for _, k := range kem.ListKEMs() {
		logger.Printf("  - %s\n", k)
	}
	logger.Println()

	var serverPrivateKey kem.PrivateKey
	var serverPublicKey kem.PublicKey

	kem1, err := kem.GetKEM(*kem1Type)
	if err != nil {
		logger.Fatalf("%sError: %s%s\n", colorRed, err, colorReset)
	}
	kem2, err := kem.GetKEM(*kem2Type)
	if err != nil {
		logger.Fatalf("%sError: %s%s\n", colorRed, err, colorReset)
	}
	// Generate a new key pair if requested
	if *genKeyFile != "" {
		serverPublicKey, serverPrivateKey, err = generateAndSaveKeyPair(kem1, *genKeyFile, logger)
		if err != nil {
			logger.Fatalf("%sError generating key pair: %s%s\n", colorRed, err, colorReset)
		}
	} else if *keyFile != "" {
		// Load existing key pair
		serverPrivateKey, err = loadPrivateKey(kem1, *keyFile, logger)
		if err != nil {
			logger.Fatalf("%sError loading key: %s%s\n", colorRed, err, colorReset)
		}
		serverPublicKey = serverPrivateKey.PublicKey()
	} else {
		// Generate ephemeral key pair
		logger.Printf("%sGenerating ephemeral %s key pair...%s\n", colorYellow, *kem1Type, colorReset)
		serverPublicKey, serverPrivateKey, err = kem1.GenerateKeyPair(kem1.Setup(), nil)
		if err != nil {
			logger.Fatalf("%sError generating key pair: %s%s\n", colorRed, err, colorReset)
		}
	}

	// Print public key for client use, if too long, cut it off
	if len(serverPublicKey.Bytes()) > 32 {
		logger.Printf("%sServer public key (for client use): %x...%s\n", colorGreen, serverPublicKey.Bytes()[:32], colorReset)
	} else {
		logger.Printf("%sServer public key (for client use): %x%s\n", colorGreen, serverPublicKey.Bytes(), colorReset)
	}
	logger.Printf("%sLong Term Key algorithm: %s%s\n\n", colorGreen, colorReset, serverPublicKey.Algorithm())

	if *genKeyFile != "" {
		// We only generated a key pair, so exit
		return
	}
	// Configure server

	serverConfig := &protocol.Config{
		KEM1:                kem1,
		KEM2:                kem2,
		SymmetricEncryption: protocol.DefaultConfig().SymmetricEncryption,
	}
	options := protocol.NewSessionOptions().WithServerPrivateKey(serverPrivateKey)

	// Create TCP listener
	addr := fmt.Sprintf(":%d", *port)
	tcpConfig := &net.ListenConfig{}
	listener, err := tcpConfig.Listen(context.Background(), "tcp4", addr)
	if err != nil {
		logger.Fatalf("%sError creating listener: %s%s\n", colorRed, err, colorReset)
	}
	defer listener.Close()

	logger.Printf("%sServer listening on port %d...%s\n", colorGreen, *port, colorReset)

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("%sError accepting connection: %s%s\n", colorRed, err, colorReset)
			continue
		}

		// Handle each connection in a goroutine
		go handleConnection(conn, serverConfig, options, logger, *verbose)
	}
}

func handleConnection(conn net.Conn, config *protocol.Config, options *protocol.SessionOptions, logger *log.Logger, verbose bool) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	logger.Printf("%sNew connection from %s%s\n", colorBlue, remoteAddr, colorReset)

	// Create server instance
	server, err := protocol.NewServer(config, options)
	if err != nil {
		logger.Printf("%sError creating server: %s%s\n", colorRed, err, colorReset)
		return
	}
	defer server.Reset()

	// Read client hello message
	logger.Printf("%s[%s] Waiting for ClientHello...%s\n", colorCyan, remoteAddr, colorReset)

	// Read message length, with 32-bit length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		logger.Printf("%s[%s] Error reading message length: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}

	messageLen := binary.BigEndian.Uint32(lenBuf)
	messageBuf := make([]byte, messageLen)
	if _, err := io.ReadFull(conn, messageBuf); err != nil {
		logger.Printf("%s[%s] Error reading client hello: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}

	// Unmarshal client hello
	serializer := &protocol.DefaultSerializer{}
	clientHello, err := serializer.UnmarshalClientHello(messageBuf)
	if err != nil {
		logger.Printf("%s[%s] Error unmarshalling client hello: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}

	logger.Printf("%s[%s] Received ClientHello%s\n", colorGreen, remoteAddr, colorReset)
	if verbose {
		logger.Printf("  KEM1 Type: %s\n", clientHello.KEM1Type)
		logger.Printf("  KEM2 Type: %s\n", clientHello.KEM2Type)
		logger.Printf("  Ephemeral public key length: %d bytes\n", len(clientHello.EphemeralPublicKey))
		logger.Printf("  Ciphertext1 length: %d bytes\n", len(clientHello.Ciphertext1))
		logger.Printf("  Encrypted payload length: %d bytes\n", len(clientHello.EncryptedPayload))
	}

	// Process client hello (extract 0-RTT data if present)
	startTime := time.Now()
	zeroRTTData, err := server.ProcessClientHello(clientHello)
	if err != nil {
		logger.Printf("%s[%s] Error processing client hello: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}
	processingTime := time.Since(startTime)

	// Log 0-RTT data if present
	if len(zeroRTTData) > 0 {
		logger.Printf("%s[%s] Received 0-RTT data: %s%s\n", colorPurple, remoteAddr, string(zeroRTTData), colorReset)
	} else {
		logger.Printf("%s[%s] No 0-RTT data received%s\n", colorYellow, remoteAddr, colorReset)
	}

	// Generate server response
	logger.Printf("%s[%s] Generating server response...%s\n", colorCyan, remoteAddr, colorReset)
	payload := []byte("Hello from TIMKE server! This is stage-2 protected data.")
	serverResponse, err := server.GenerateServerResponse(payload)
	if err != nil {
		logger.Printf("%s[%s] Error generating server response: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}

	// Serialize and send server response
	responseBytes, err := serializer.MarshalServerResponse(serverResponse)
	if err != nil {
		logger.Printf("%s[%s] Error marshalling server response: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}

	// First send the length as 4 bytes
	binary.BigEndian.PutUint32(lenBuf, uint32(len(responseBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		logger.Printf("%s[%s] Error sending response length: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}

	// Then send the actual response
	if _, err := conn.Write(responseBytes); err != nil {
		logger.Printf("%s[%s] Error sending server response: %s%s\n", colorRed, remoteAddr, err, colorReset)
		return
	}

	logger.Printf("%s[%s] Sent server response (%d bytes)%s\n", colorGreen, remoteAddr, len(responseBytes), colorReset)

	// Session established!
	sessionKey := server.GetSessionKey()
	logger.Printf("%s[%s] Session established!%s\n", colorGreen, remoteAddr, colorReset)
	logger.Printf("%s[%s] Protocol completed in %v%s\n", colorBlue, remoteAddr, processingTime, colorReset)
	if verbose {
		logger.Printf("%s[%s] Session key (first 8 bytes): %x%s\n", colorPurple, remoteAddr, sessionKey[:min(8, len(sessionKey))], colorReset)
	}

	// Wait for client messages
	for {
		// Read message length
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			if err == io.EOF {
				logger.Printf("%s[%s] Client disconnected%s\n", colorYellow, remoteAddr, colorReset)
			} else {
				logger.Printf("%s[%s] Error reading message length: %s%s\n", colorRed, remoteAddr, err, colorReset)
			}
			return
		}

		messageLen = binary.BigEndian.Uint32(lenBuf)
		messageBuf = make([]byte, messageLen)
		if _, err := io.ReadFull(conn, messageBuf); err != nil {
			logger.Printf("%s[%s] Error reading message: %s%s\n", colorRed, remoteAddr, err, colorReset)
			return
		}

		// Decrypt message
		plaintext, err := server.Decrypt(messageBuf)
		if err != nil {
			logger.Printf("%s[%s] Error decrypting message: %s%s\n", colorRed, remoteAddr, err, colorReset)
			return
		}

		logger.Printf("%s[%s] Received encrypted message: %s%s\n", colorPurple, remoteAddr, string(plaintext), colorReset)

		// Send response
		response := []byte(fmt.Sprintf("Server received: %s (at %s)", plaintext, time.Now().Format(time.RFC3339)))
		encryptedResponse, err := server.Encrypt(response)
		if err != nil {
			logger.Printf("%s[%s] Error encrypting response: %s%s\n", colorRed, remoteAddr, err, colorReset)
			return
		}

		// Send length as 2 bytes
		lenBuf[0] = byte(len(encryptedResponse) >> 8)
		lenBuf[1] = byte(len(encryptedResponse))
		if _, err := conn.Write(lenBuf); err != nil {
			logger.Printf("%s[%s] Error sending response length: %s%s\n", colorRed, remoteAddr, err, colorReset)
			return
		}

		// Send encrypted response
		if _, err := conn.Write(encryptedResponse); err != nil {
			logger.Printf("%s[%s] Error sending response: %s%s\n", colorRed, remoteAddr, err, colorReset)
			return
		}

		logger.Printf("%s[%s] Sent encrypted response (%d bytes)%s\n", colorGreen, remoteAddr, len(encryptedResponse), colorReset)
	}
}

func generateAndSaveKeyPair(k kem.KEM, filename string, logger *log.Logger) (kem.PublicKey, kem.PrivateKey, error) {
	logger.Printf("%sGenerating new %s key pair...%s\n", colorYellow, k.Setup().Name, colorReset)

	publicKey, privateKey, err := k.GenerateKeyPair(k.Setup(), nil)
	if err != nil {
		return nil, nil, err
	}

	// Save private key to file
	privateKeyBytes := privateKey.Bytes()
	if err := os.WriteFile(filename, privateKeyBytes, 0o600); err != nil {
		return nil, nil, err
	}

	// Save public key to file as well
	publicKeyBytes := publicKey.Bytes()
	if err := os.WriteFile(filename+".pub", publicKeyBytes, 0o644); err != nil {
		return nil, nil, err
	}

	logger.Printf("%sKey pair generated and saved to %s and %s.pub%s\n",
		colorGreen, filename, filename, colorReset)

	return publicKey, privateKey, nil
}

func loadPrivateKey(k kem.KEM, filename string, logger *log.Logger) (kem.PrivateKey, error) {
	logger.Printf("%sLoading private key from %s...%s\n", colorYellow, filename, colorReset)

	privateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	privateKey, err := k.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	logger.Printf("%sPrivate key loaded successfully%s\n", colorGreen, colorReset)

	return privateKey, nil
}

func printBanner(logger *log.Logger) {
	banner := `
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║  ████████╗██╗███╗   ███╗██╗  ██╗███████╗                   ║
║  ╚══██╔══╝██║████╗ ████║██║ ██╔╝██╔════╝                   ║
║     ██║   ██║██╔████╔██║█████╔╝ █████╗                     ║
║     ██║   ██║██║╚██╔╝██║██╔═██╗ ██╔══╝                     ║
║     ██║   ██║██║ ╚═╝ ██║██║  ██╗███████╗                   ║
║     ╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝                   ║
║                                                            ║
║     TIghtly secure Multi-stage Key Exchange - Server       ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
`
	logger.Println(colorCyan + banner + colorReset)
}
