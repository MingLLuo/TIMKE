package kem

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type BenchmarkResult struct {
	Algorithm      string
	Operation      string
	AvgTime        time.Duration
	Iterations     int
	MemoryUsage    uint64 // in KB
	KeySize        int
	CiphertextSize int
	SharedKeySize  int
}

type BenchmarkOptions struct {
	Iterations int
	KEMNames   []string
	Verbose    bool
	CSVOutput  string
}

func DefaultBenchmarkOptions() BenchmarkOptions {
	return BenchmarkOptions{
		Iterations: 100,
		KEMNames:   []string{},
		Verbose:    true,
		CSVOutput:  "",
	}
}

func RunBenchmarks(options BenchmarkOptions) ([]BenchmarkResult, error) {
	var results []BenchmarkResult

	kemNames := options.KEMNames
	if len(kemNames) == 0 {
		kemNames = ListKEMs()
		sort.Strings(kemNames)
	}

	for _, kemName := range kemNames {
		if options.Verbose {
			fmt.Printf("Benchmarking %s...\n", kemName)
		}

		kem, err := GetKEM(kemName)
		if err != nil {
			fmt.Printf("Error getting KEM %s: %v\n", kemName, err)
			continue
		}

		if options.Verbose {
			fmt.Printf("  - KeyGen...\n")
		}
		keyGenResult, err := benchmarkKeyGen(kem, kemName, options.Iterations)
		if err != nil {
			fmt.Printf("Error benchmarking key generation for %s: %v\n", kemName, err)
		} else {
			results = append(results, keyGenResult)
		}

		pk, sk, err := kem.GenerateKeyPair(kem.Setup(), rand.Reader)
		if err != nil {
			fmt.Printf("Error generating key pair for %s: %v\n", kemName, err)
			continue
		}

		if options.Verbose {
			fmt.Printf("  - Encap...\n")
		}
		encapResult, err := benchmarkEncap(kem, pk, kemName, options.Iterations)
		if err != nil {
			fmt.Printf("Error benchmarking encapsulation for %s: %v\n", kemName, err)
		} else {
			results = append(results, encapResult)
		}

		ct, ss, err := kem.Encapsulate(pk, rand.Reader)
		if err != nil {
			fmt.Printf("Error encapsulating for %s: %v\n", kemName, err)
			continue
		}

		if options.Verbose {
			fmt.Printf("  - Decap...\n")
		}
		decapResult, err := benchmarkDecap(kem, sk, ct, kemName, options.Iterations)
		if err != nil {
			fmt.Printf("Error benchmarking decapsulation for %s: %v\n", kemName, err)
		} else {
			decapResult.SharedKeySize = len(ss)
			results = append(results, decapResult)
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

func benchmarkKeyGen(kem KEM, kemName string, iterations int) (BenchmarkResult, error) {
	result := BenchmarkResult{
		Algorithm:  kemName,
		Operation:  "KeyGen",
		Iterations: iterations,
	}

	// Run garbage collection before measuring
	runtime.GC()

	var memStatsBefore, memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	var pk PublicKey
	var _ PrivateKey
	var err error

	// Warm-up run
	_, _, _ = kem.GenerateKeyPair(kem.Setup(), rand.Reader)

	// Benchmark
	startTime := time.Now()
	for i := 0; i < iterations; i++ {
		pk, _, err = kem.GenerateKeyPair(kem.Setup(), rand.Reader)
		if err != nil {
			return result, fmt.Errorf("key generation failed: %w", err)
		}
	}
	elapsed := time.Since(startTime)

	runtime.ReadMemStats(&memStatsAfter)

	// Calculate results
	result.AvgTime = elapsed / time.Duration(iterations)
	result.MemoryUsage = (memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc) / 1024 // Convert to KB

	// Get key sizes
	if pk != nil {
		result.KeySize = len(pk.Bytes())
	}

	return result, nil
}

// benchmarkEncap measures encapsulation performance
func benchmarkEncap(kem KEM, pk PublicKey, kemName string, iterations int) (BenchmarkResult, error) {
	result := BenchmarkResult{
		Algorithm:  kemName,
		Operation:  "Encap",
		Iterations: iterations,
	}

	// Run garbage collection before measuring
	runtime.GC()

	var memStatsBefore, memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	var ct, ss []byte
	var err error

	// Warm-up run
	_, _, _ = kem.Encapsulate(pk, rand.Reader)

	// Benchmark
	startTime := time.Now()
	for i := 0; i < iterations; i++ {
		ct, ss, err = kem.Encapsulate(pk, rand.Reader)
		if err != nil {
			return result, fmt.Errorf("encapsulation failed: %w", err)
		}
	}
	elapsed := time.Since(startTime)

	runtime.ReadMemStats(&memStatsAfter)

	// Calculate results
	result.AvgTime = elapsed / time.Duration(iterations)
	result.MemoryUsage = (memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc) / 1024 // Convert to KB

	// Get sizes
	if ct != nil {
		result.CiphertextSize = len(ct)
	}
	if ss != nil {
		result.SharedKeySize = len(ss)
	}

	return result, nil
}

// benchmarkDecap measures decapsulation performance
func benchmarkDecap(kem KEM, sk PrivateKey, ct []byte, kemName string, iterations int) (BenchmarkResult, error) {
	result := BenchmarkResult{
		Algorithm:  kemName,
		Operation:  "Decap",
		Iterations: iterations,
	}

	// Run garbage collection before measuring
	runtime.GC()

	var memStatsBefore, memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	var ss []byte
	var err error

	// Warm-up run
	_, _ = kem.Decapsulate(sk, ct)

	// Benchmark
	startTime := time.Now()
	for i := 0; i < iterations; i++ {
		ss, err = kem.Decapsulate(sk, ct)
		if err != nil {
			return result, fmt.Errorf("decapsulation failed: %w", err)
		}
	}
	elapsed := time.Since(startTime)

	runtime.ReadMemStats(&memStatsAfter)

	// Calculate results
	result.AvgTime = elapsed / time.Duration(iterations)
	result.MemoryUsage = (memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc) / 1024 // Convert to KB

	// Get size
	if ss != nil {
		result.SharedKeySize = len(ss)
	}

	return result, nil
}

// FormatResults returns a string with formatted results
func FormatResults(results []BenchmarkResult) string {
	var sb strings.Builder

	// Group results by algorithm for easier comparison
	algorithmMap := make(map[string][]BenchmarkResult)
	for _, result := range results {
		algorithmMap[result.Algorithm] = append(algorithmMap[result.Algorithm], result)
	}

	// Get all unique algorithms and sort them
	algorithms := make([]string, 0, len(algorithmMap))
	for alg := range algorithmMap {
		algorithms = append(algorithms, alg)
	}
	sort.Strings(algorithms)

	// Print header
	sb.WriteString("KEM Performance Benchmark Results\n")
	sb.WriteString("===============================\n\n")

	// Time performance table
	sb.WriteString("Time Performance (microseconds)\n")
	sb.WriteString("---------------------------------\n")
	sb.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\n", "Algorithm", "KeyGen", "Encap", "Decap"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, alg := range algorithms {
		results := algorithmMap[alg]
		keyGenTime := "N/A"
		encapTime := "N/A"
		decapTime := "N/A"

		for _, res := range results {
			switch res.Operation {
			case "KeyGen":
				keyGenTime = fmt.Sprintf("%.2f", float64(res.AvgTime.Microseconds()))
			case "Encap":
				encapTime = fmt.Sprintf("%.2f", float64(res.AvgTime.Microseconds()))
			case "Decap":
				decapTime = fmt.Sprintf("%.2f", float64(res.AvgTime.Microseconds()))
			}
		}

		sb.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\n", alg, keyGenTime, encapTime, decapTime))
	}
	sb.WriteString("\n")

	// Memory usage table
	sb.WriteString("Memory Usage (KB)\n")
	sb.WriteString("------------------\n")
	sb.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\n", "Algorithm", "KeyGen", "Encap", "Decap"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, alg := range algorithms {
		results := algorithmMap[alg]
		keyGenMem := "N/A"
		encapMem := "N/A"
		decapMem := "N/A"

		for _, res := range results {
			switch res.Operation {
			case "KeyGen":
				keyGenMem = fmt.Sprintf("%.2f", float64(res.MemoryUsage))
			case "Encap":
				encapMem = fmt.Sprintf("%.2f", float64(res.MemoryUsage))
			case "Decap":
				decapMem = fmt.Sprintf("%.2f", float64(res.MemoryUsage))
			}
		}

		sb.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\n", alg, keyGenMem, encapMem, decapMem))
	}
	sb.WriteString("\n")

	// Sizes table
	sb.WriteString("Sizes (bytes)\n")
	sb.WriteString("-------------\n")
	sb.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\n", "Algorithm", "Public Key", "Ciphertext", "Shared Key"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")

	for _, alg := range algorithms {
		results := algorithmMap[alg]
		pubKeySize := "N/A"
		ctSize := "N/A"
		skSize := "N/A"

		for _, res := range results {
			switch res.Operation {
			case "KeyGen":
				pubKeySize = strconv.Itoa(res.KeySize)
			case "Encap":
				ctSize = strconv.Itoa(res.CiphertextSize)
				skSize = strconv.Itoa(res.SharedKeySize)
			}
		}

		sb.WriteString(fmt.Sprintf("%-20s %-15s %-15s %-15s\n", alg, pubKeySize, ctSize, skSize))
	}

	return sb.String()
}

// writeResultsToCSV writes benchmark results to a CSV file
func writeResultsToCSV(results []BenchmarkResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	header := "Algorithm,Operation,AvgTime(μs),Iterations,MemoryUsage(KB),KeySize,CiphertextSize,SharedKeySize\n"
	if _, err := file.WriteString(header); err != nil {
		return err
	}

	// Write data rows
	for _, result := range results {
		line := fmt.Sprintf("%s,%s,%.2f,%d,%.2f,%d,%d,%d\n",
			result.Algorithm,
			result.Operation,
			float64(result.AvgTime.Microseconds()),
			result.Iterations,
			float64(result.MemoryUsage),
			result.KeySize,
			result.CiphertextSize,
			result.SharedKeySize)

		if _, err := file.WriteString(line); err != nil {
			return err
		}
	}

	return nil
}
