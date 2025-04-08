package protocol

import (
	"TIMKE/pkg/kem"
	"fmt"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"
)

type TestCase struct {
	Name  string
	KEM1  string
	KEM2  string
	Iters int
}

type BenchmarkResult struct {
	TestCase       TestCase
	Phase1Time     time.Duration
	Phase2Time     time.Duration
	TotalTime      time.Duration
	MemoryUsageKB  uint64
	KeySizeBytes   int
	PayloadSizeRTT int
}

type BenchmarkOptions struct {
	TestCases      []TestCase
	ZeroRTTPayload []byte
	Verbose        bool
	CSVOutput      string
}

func DefaultBenchmarkOptions() BenchmarkOptions {
	return BenchmarkOptions{
		TestCases: []TestCase{
			{Name: "OWChCCA-16 + ML-KEM-512", KEM1: "OWChCCA-16", KEM2: "ML-KEM-512", Iters: 10},
			{Name: "OWChCCA-16 + ML-KEM-768", KEM1: "OWChCCA-16", KEM2: "ML-KEM-768", Iters: 10},
			{Name: "OWChCCA-16 + ML-KEM-1024", KEM1: "OWChCCA-16", KEM2: "ML-KEM-1024", Iters: 10},
			{Name: "ML-KEM-512 + ML-KEM-512", KEM1: "ML-KEM-512", KEM2: "ML-KEM-512", Iters: 10},
			{Name: "ML-KEM-768 + ML-KEM-768", KEM1: "ML-KEM-768", KEM2: "ML-KEM-768", Iters: 10},
			{Name: "ML-KEM-1024 + ML-KEM-1024", KEM1: "ML-KEM-1024", KEM2: "ML-KEM-1024", Iters: 10},
		},
		ZeroRTTPayload: []byte("Hello from TIMKE client! This is 0-RTT data."),
		Verbose:        true,
		CSVOutput:      "",
	}
}

func RunProtocolBenchmark(options BenchmarkOptions) ([]BenchmarkResult, error) {
	var results []BenchmarkResult

	if options.Verbose {
		fmt.Println("Starting TIMKE protocol benchmark...")
		fmt.Printf("Testing %d KEM combinations\n", len(options.TestCases))
		fmt.Println()
	}

	for _, tc := range options.TestCases {
		if options.Verbose {
			fmt.Printf("Testing %s (%d iterations)...\n", tc.Name, tc.Iters)
		}

		result, err := runSingleTest(tc, options.ZeroRTTPayload, options.Verbose)
		if err != nil {
			fmt.Printf("Error testing %s: %v\n", tc.Name, err)
			continue
		}

		results = append(results, result)

		if options.Verbose {
			fmt.Printf("  Phase 1: %.2f ms\n", float64(result.Phase1Time.Microseconds())/1000)
			fmt.Printf("  Phase 2: %.2f ms\n", float64(result.Phase2Time.Microseconds())/1000)
			fmt.Printf("  Total: %.2f ms\n", float64(result.TotalTime.Microseconds())/1000)
			fmt.Printf("  Memory: %d KB\n", result.MemoryUsageKB)
			fmt.Printf("  Key size: %d bytes\n", result.KeySizeBytes)
			fmt.Println()
		}
	}

	if options.CSVOutput != "" {
		err := writeResultsToCSV(results, options.CSVOutput)
		if err != nil {
			fmt.Printf("Error writing results to CSV: %v\n", err)
		}
	}

	return results, nil
}

func runSingleTest(tc TestCase, zeroRTTPayload []byte, verbose bool) (BenchmarkResult, error) {
	result := BenchmarkResult{
		TestCase: tc,
	}

	kem1, err := kem.GetKEM(tc.KEM1)
	if err != nil {
		return result, fmt.Errorf("failed to get KEM1 %s: %v", tc.KEM1, err)
	}

	kem2, err := kem.GetKEM(tc.KEM2)
	if err != nil {
		return result, fmt.Errorf("failed to get KEM2 %s: %v", tc.KEM2, err)
	}

	config := &Config{
		KEM1:                kem1,
		KEM2:                kem2,
		SymmetricEncryption: DefaultConfig().SymmetricEncryption,
	}

	var totalPhase1 time.Duration
	var totalPhase2 time.Duration
	var totalMem uint64
	keySize := 0

	for i := 0; i < tc.Iters; i++ {
		runtime.GC()

		var memStatsBefore, memStatsAfter runtime.MemStats
		runtime.ReadMemStats(&memStatsBefore)

		serverPubKey, serverPrivKey, err := kem1.GenerateKeyPair(kem1.Setup(), nil)
		if err != nil {
			return result, fmt.Errorf("failed to generate server key pair: %v", err)
		}

		clientOptions := NewSessionOptions().WithServerPublicKey(serverPubKey)
		client, err := NewClient(config, clientOptions)
		if err != nil {
			return result, fmt.Errorf("failed to create client: %v", err)
		}

		serverOptions := NewSessionOptions().WithServerPrivateKey(serverPrivKey)
		server, err := NewServer(config, serverOptions)
		if err != nil {
			return result, fmt.Errorf("failed to create server: %v", err)
		}

		startPhase1 := time.Now()
		clientHello, err := client.GenerateClientHello(zeroRTTPayload)
		if err != nil {
			return result, fmt.Errorf("failed to generate client hello: %v", err)
		}

		zeroRTTData, err := server.ProcessClientHello(clientHello)
		if err != nil {
			return result, fmt.Errorf("failed to process client hello: %v", err)
		}
		phase1Time := time.Since(startPhase1)
		totalPhase1 += phase1Time

		if i == 0 && keySize == 0 {
			keySize = len(serverPubKey.Bytes())
		}

		startPhase2 := time.Now()
		serverPayload := []byte("Hello from TIMKE server! This is stage-2 protected data.")
		serverResponse, err := server.GenerateServerResponse(serverPayload)
		if err != nil {
			return result, fmt.Errorf("failed to generate server response: %v", err)
		}

		serverData, err := client.ProcessServerResponse(serverResponse)
		if err != nil {
			return result, fmt.Errorf("failed to process server response: %v", err)
		}
		phase2Time := time.Since(startPhase2)
		totalPhase2 += phase2Time

		if len(zeroRTTData) == 0 || string(zeroRTTData) != string(zeroRTTPayload) {
			return result, fmt.Errorf("0-RTT data mismatch")
		}

		if len(serverData) == 0 || string(serverData) != string(serverPayload) {
			return result, fmt.Errorf("server data mismatch")
		}

		runtime.ReadMemStats(&memStatsAfter)
		memUsage := (memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc) / 1024
		totalMem += memUsage
	}

	result.Phase1Time = totalPhase1 / time.Duration(tc.Iters)
	result.Phase2Time = totalPhase2 / time.Duration(tc.Iters)
	result.TotalTime = result.Phase1Time + result.Phase2Time
	result.MemoryUsageKB = totalMem / uint64(tc.Iters)
	result.KeySizeBytes = keySize
	result.PayloadSizeRTT = len(zeroRTTPayload)

	return result, nil
}

func FormatResults(results []BenchmarkResult) string {
	var sb strings.Builder

	w := tabwriter.NewWriter(&sb, 0, 0, 3, ' ', tabwriter.TabIndent)

	fmt.Fprintln(w, "TIMKE Protocol Performance Benchmark Results")
	fmt.Fprintln(w, "=========================================")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Performance (ms)\t")
	fmt.Fprintln(w, "KEM Combination\tPhase 1\tPhase 2\tTotal\tMemory (KB)\tKey Size (bytes)")
	fmt.Fprintln(w, "-------------------------------------------------------------")

	for _, result := range results {
		fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%.2f\t%d\t%d\n",
			result.TestCase.Name,
			float64(result.Phase1Time.Microseconds())/1000,
			float64(result.Phase2Time.Microseconds())/1000,
			float64(result.TotalTime.Microseconds())/1000,
			result.MemoryUsageKB,
			result.KeySizeBytes)
	}

	w.Flush()
	return sb.String()
}

func writeResultsToCSV(results []BenchmarkResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	header := "KEM Combination,Phase 1 (ms),Phase 2 (ms),Total (ms),Memory (KB),Key Size (bytes),Iterations\n"
	if _, err := file.WriteString(header); err != nil {
		return err
	}

	for _, result := range results {
		line := fmt.Sprintf("%s,%.3f,%.3f,%.3f,%d,%d,%d\n",
			result.TestCase.Name,
			float64(result.Phase1Time.Microseconds())/1000,
			float64(result.Phase2Time.Microseconds())/1000,
			float64(result.TotalTime.Microseconds())/1000,
			result.MemoryUsageKB,
			result.KeySizeBytes,
			result.TestCase.Iters)

		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}

	return nil
}
