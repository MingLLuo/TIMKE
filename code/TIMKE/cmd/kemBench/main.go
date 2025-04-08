package main

import (
	"TIMKE/pkg/kem"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// Parse command-line arguments
	iterations := flag.Int("iterations", 5, "Number of iterations for each benchmark")
	algorithms := flag.String("algorithms", "", "Comma-separated list of algorithms to benchmark (empty for all)")
	outputCSV := flag.String("csv", "", "Output results to CSV file")
	verbose := flag.Bool("verbose", true, "Print progress information")
	listAlgs := flag.Bool("list", true, "List available algorithms and exit")
	flag.Parse()

	if *listAlgs {
		fmt.Println("Available KEM algorithms:")
		for _, name := range kem.ListKEMs() {
			fmt.Printf("  - %s\n", name)
		}
		//os.Exit(0)
	}

	options := kem.DefaultBenchmarkOptions()
	options.Iterations = *iterations
	options.Verbose = *verbose
	options.CSVOutput = *outputCSV

	// Parse algorithm list if provided
	if *algorithms != "" {
		options.KEMNames = strings.Split(*algorithms, ",")
	}

	// Run benchmarks
	if *verbose {
		fmt.Printf("Running benchmarks with %d iterations...\n", *iterations)
	}
	results, err := kem.RunBenchmarks(options)
	if err != nil {
		fmt.Printf("Error running benchmarks: %v\n", err)
		os.Exit(1)
	}

	formattedResults := kem.FormatResults(results)
	fmt.Println(formattedResults)

	if *outputCSV != "" && *verbose {
		fmt.Printf("Results saved to %s\n", *outputCSV)
	}
}
