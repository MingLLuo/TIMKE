package main

import (
	"TIMKE/pkg/protocol"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	iterations := flag.Int("iterations", 10, "Number of iterations for each benchmark")
	kemCases := flag.String("kem-cases", "", "Comma-separated list of KEM combinations to benchmark (format: KEM1+KEM2,KEM3+KEM4)")
	outputCSV := flag.String("csv", "", "Output results to CSV file")
	verbose := flag.Bool("verbose", true, "Print progress information")
	zeroRTT := flag.String("0rtt", "Hello from TIMKE client! This is 0-RTT data.", "0-RTT payload to use")
	listDefault := flag.Bool("list-default", false, "List default KEM combinations and exit")
	flag.Parse()

	options := protocol.DefaultBenchmarkOptions()
	options.Verbose = *verbose
	options.CSVOutput = *outputCSV
	options.ZeroRTTPayload = []byte(*zeroRTT)

	if *listDefault {
		fmt.Println("Default KEM combinations for benchmarking:")
		for _, tc := range options.TestCases {
			fmt.Printf("  - %s (%s + %s)\n", tc.Name, tc.KEM1, tc.KEM2)
		}
		return
	}

	if *kemCases != "" {
		customTestCases := []protocol.TestCase{}
		combos := strings.Split(*kemCases, ",")

		for _, combo := range combos {
			parts := strings.Split(combo, "+")
			if len(parts) != 2 {
				fmt.Printf("Invalid KEM combination format: %s (should be KEM1+KEM2)\n", combo)
				continue
			}

			kem1 := strings.TrimSpace(parts[0])
			kem2 := strings.TrimSpace(parts[1])
			name := fmt.Sprintf("%s + %s", kem1, kem2)

			customTestCases = append(customTestCases, protocol.TestCase{
				Name:  name,
				KEM1:  kem1,
				KEM2:  kem2,
				Iters: *iterations,
			})
		}

		if len(customTestCases) > 0 {
			options.TestCases = customTestCases
		}
	} else {
		for i := range options.TestCases {
			options.TestCases[i].Iters = *iterations
		}
	}

	if *verbose {
		fmt.Printf("Running protocol benchmarks with %d iterations per test...\n", *iterations)
		fmt.Printf("Testing %d KEM combinations\n", len(options.TestCases))
	}

	results, err := protocol.RunProtocolBenchmark(options)
	if err != nil {
		fmt.Printf("Error running benchmarks: %v\n", err)
		os.Exit(1)
	}

	formattedResults := protocol.FormatResults(results)
	fmt.Println(formattedResults)

	if *outputCSV != "" && *verbose {
		fmt.Printf("Results saved to %s\n", *outputCSV)
	}
}
