package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
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
	// Command line flags
	var (
		host          = flag.String("host", "localhost", "Server hostname or IP")
		port          = flag.Int("port", 8443, "Server port")
		serverPubKey  = flag.String("server-key", "", "Server public key in hex format")
		serverKeyFile = flag.String("server-key-file", "", "File containing the server public key")
		kem1Type      = flag.String("kem1", "ML-KEM-768", "KEM1 type for server key (OW-ChCCA-KEM, ML-KEM-768, etc.)")
		kem2Type      = flag.String("kem2", "ML-KEM-768", "KEM2 type for ephemeral key (ML-KEM-1024, X25519-ML-KEM-768, etc.)")
		zeroRTTMsg    = flag.String("0rtt", "Hello from TIMKE client! This is 0-RTT data.", "0-RTT message to send (empty to disable)")
		interactive   = flag.Bool("i", false, "Interactive mode (send/receive messages after key exchange)")
		verbose       = flag.Bool("v", false, "Verbose output")
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

	// Get the server public key
	var serverPublicKeyBytes []byte
	var err error

	if *serverKeyFile != "" {
		// Load from file
		serverPublicKeyBytes, err = os.ReadFile(*serverKeyFile)
		if err != nil {
			logger.Fatalf("%sError reading server key file: %s%s\n", colorRed, err, colorReset)
		}
	} else if *serverPubKey != "" {
		// Parse hex string
		serverPublicKeyBytes, err = hex.DecodeString(*serverPubKey)
		if err != nil {
			logger.Fatalf("%sError decoding server public key hex: %s%s\n", colorRed, err, colorReset)
		}
	} else {
		logger.Fatalf("%sError: Either --server-key or --server-key-file must be provided%s\n", colorRed, colorReset)
	}

	kem1, err := kem.GetKEM(*kem1Type)
	if err != nil {
		logger.Fatalf("%sError: KEM1 type '%s' not found: %s%s\n", colorRed, *kem1Type, err, colorReset)
	}
	kem2, err := kem.GetKEM(*kem2Type)
	if err != nil {
		logger.Fatalf("%sError: KEM2 type '%s' not found: %s%s\n", colorRed, *kem2Type, err, colorReset)
	}

	// Parse server public key
	serverPublicKey, err := kem1.ParsePublicKey(serverPublicKeyBytes)
	if err != nil {
		logger.Fatalf("%sError parsing server public key: %s%s\n", colorRed, err, colorReset)
	}

	logger.Printf("%sUsing server key: %s%s\n", colorGreen, serverPublicKey.Algorithm(), colorReset)

	// Create client configuration
	config := &protocol.Config{
		KEM1:                kem1,
		KEM2:                kem2,
		SymmetricEncryption: protocol.DefaultConfig().SymmetricEncryption,
	}

	// Create client options
	options := protocol.NewSessionOptions().WithServerPublicKey(serverPublicKey)

	// Create client
	client, err := protocol.NewClient(config, options)
	if err != nil {
		logger.Fatalf("%sError creating client: %s%s\n", colorRed, err, colorReset)
	}

	// Connect to server
	serverAddr := fmt.Sprintf("%s:%d", *host, *port)
	logger.Printf("%sConnecting to %s...%s\n", colorYellow, serverAddr, colorReset)
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		logger.Fatalf("%sError connecting to server: %s%s\n", colorRed, err, colorReset)
	}
	defer conn.Close()
	logger.Printf("%sConnected to %s%s\n", colorGreen, serverAddr, colorReset)

	// Determine 0-RTT payload
	var zeroRTTData []byte
	if *zeroRTTMsg != "" {
		zeroRTTData = []byte(*zeroRTTMsg)
	}

	// Start protocol - generate ClientHello
	startTime := time.Now()
	logger.Printf("%sGenerating ClientHello...%s\n", colorCyan, colorReset)
	clientHello, err := client.GenerateClientHello(zeroRTTData)
	if err != nil {
		logger.Fatalf("%sError generating ClientHello: %s%s\n", colorRed, err, colorReset)
	}

	// Visualize the protocol - Stage 1
	if *verbose {
		logger.Printf("%s---------- Protocol Stage 1 ----------%s\n", colorPurple, colorReset)
		logger.Printf("KEM1 Type: %s\n", clientHello.KEM1Type)
		logger.Printf("KEM2 Type: %s\n", clientHello.KEM2Type)
		logger.Printf("Ephemeral public key length: %d bytes\n", len(clientHello.EphemeralPublicKey))
		logger.Printf("Ciphertext1 length: %d bytes\n", len(clientHello.Ciphertext1))
		if zeroRTTData != nil {
			logger.Printf("0-RTT data: %s\n", *zeroRTTMsg)
			logger.Printf("Encrypted payload length: %d bytes\n", len(clientHello.EncryptedPayload))
		} else {
			logger.Printf("No 0-RTT data\n")
		}
	}

	// Serialize and send ClientHello
	serializer := &protocol.DefaultSerializer{}
	clientHelloBytes, err := serializer.MarshalClientHello(clientHello)
	if err != nil {
		logger.Fatalf("%sError marshalling ClientHello: %s%s\n", colorRed, err, colorReset)
	}

	// First send the length as 4 bytes, 32 bit
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(clientHelloBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		logger.Fatalf("%sError sending ClientHello length: %s%s\n", colorRed, err, colorReset)
	}

	// Then send the actual ClientHello
	if _, err := conn.Write(clientHelloBytes); err != nil {
		logger.Fatalf("%sError sending ClientHello: %s%s\n", colorRed, err, colorReset)
	}

	logger.Printf("%sSent ClientHello (%d bytes)%s\n", colorGreen, len(clientHelloBytes), colorReset)
	if zeroRTTData != nil {
		logger.Printf("%sSent 0-RTT data: \"%s\"%s\n", colorPurple, *zeroRTTMsg, colorReset)
	}

	// Read server response
	logger.Printf("%sWaiting for server response...%s\n", colorCyan, colorReset)

	// Read message length
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		logger.Fatalf("%sError reading server response length: %s%s\n", colorRed, err, colorReset)
	}

	messageLen := int(binary.BigEndian.Uint32(lenBuf))
	messageBuf := make([]byte, messageLen)
	if _, err := io.ReadFull(conn, messageBuf); err != nil {
		logger.Fatalf("%sError reading server response: %s%s\n", colorRed, err, colorReset)
	}

	// Unmarshal server response
	serverResponse, err := serializer.UnmarshalServerResponse(messageBuf)
	if err != nil {
		logger.Fatalf("%sError unmarshalling server response: %s%s\n", colorRed, err, colorReset)
	}

	logger.Printf("%sReceived server response (%d bytes)%s\n", colorGreen, len(messageBuf), colorReset)

	// Visualize the protocol - Stage 2
	if *verbose {
		logger.Printf("%s---------- Protocol Stage 2 ----------%s\n", colorPurple, colorReset)
		logger.Printf("Ciphertext2 length: %d bytes\n", len(serverResponse.Ciphertext2))
		logger.Printf("Encrypted payload length: %d bytes\n", len(serverResponse.EncryptedPayload))
	}

	// Process server response
	serverData, err := client.ProcessServerResponse(serverResponse)
	if err != nil {
		logger.Fatalf("%sError processing server response: %s%s\n", colorRed, err, colorReset)
	}

	elapsedTime := time.Since(startTime)
	sessionKey := client.GetSessionKey()

	// Session established!
	logger.Printf("%sSession established! Protocol completed in %v%s\n", colorGreen, elapsedTime, colorReset)
	if *verbose && len(sessionKey) > 0 {
		logger.Printf("%sSession key (first 8 bytes): %x%s\n", colorPurple, sessionKey[:min(8, len(sessionKey))], colorReset)
	}

	// Display server data
	if len(serverData) > 0 {
		logger.Printf("%sServer data: %s%s\n", colorPurple, string(serverData), colorReset)
	}

	// Protocol complete!
	logger.Printf("%sTIMKE protocol completed successfully!%s\n", colorBlue, colorReset)

	// Interactive mode
	if *interactive {
		logger.Printf("\n%sEntering interactive mode. Type messages to send to server (type 'exit' to quit):%s\n",
			colorYellow, colorReset)

		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("> ")
			if !scanner.Scan() {
				break
			}

			message := scanner.Text()
			if strings.ToLower(message) == "exit" {
				break
			}

			// Encrypt message
			encryptedMessage, err := client.Encrypt([]byte(message))
			if err != nil {
				logger.Printf("%sError encrypting message: %s%s\n", colorRed, err, colorReset)
				continue
			}

			// Send message length
			binary.BigEndian.PutUint32(lenBuf, uint32(len(encryptedMessage)))
			if _, err := conn.Write(lenBuf); err != nil {
				logger.Printf("%sError sending message length: %s%s\n", colorRed, err, colorReset)
				break
			}

			// Send encrypted message
			if _, err := conn.Write(encryptedMessage); err != nil {
				logger.Printf("%sError sending message: %s%s\n", colorRed, err, colorReset)
				break
			}

			logger.Printf("%sSent encrypted message (%d bytes)%s\n", colorGreen, len(encryptedMessage), colorReset)

			// Read response length
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				logger.Printf("%sError reading response length: %s%s\n", colorRed, err, colorReset)
				break
			}

			messageLen := (int(lenBuf[0]) << 8) | int(lenBuf[1])
			if messageLen <= 0 || messageLen > 65535 {
				logger.Printf("%sInvalid response length: %d%s\n", colorRed, messageLen, colorReset)
				break
			}

			// Read response
			responseBuf := make([]byte, messageLen)
			if _, err := io.ReadFull(conn, responseBuf); err != nil {
				logger.Printf("%sError reading response: %s%s\n", colorRed, err, colorReset)
				break
			}

			// Decrypt response
			plaintext, err := client.Decrypt(responseBuf)
			if err != nil {
				logger.Printf("%sError decrypting response: %s%s\n", colorRed, err, colorReset)
				continue
			}

			logger.Printf("%sServer: %s%s\n", colorPurple, string(plaintext), colorReset)
		}
	}
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
║     TIghtly secure Multi-stage Key Exchange - Client       ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
`
	logger.Println(colorCyan + banner + colorReset)
}
