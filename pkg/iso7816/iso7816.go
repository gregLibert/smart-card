/*
Package iso7816 implements data structures and logic to interact with smart cards according to the ISO/IEC 7816 standard.

This package provides the fundamental building blocks for APDU (Application Protocol Data Unit) communication, including Command and Response structures, Status Word (SW) analysis, and specialized parsers for File Control Information (FCI).

# Fundamentals

The communication with a smart card is strictly synchronous:
 1. The Host sends a Command APDU (Header + Optional Body).
 2. The Card processes it and returns a Response APDU (Optional Body + Trailer SW1/SW2).

# Status Words

Every response ends with a 2-byte Status Word (SW).
  - 0x9000: Success (OK).
  - 0x61XX: Success, but response data is still available (XX bytes).
  - 0x6CXX: Error, wrong length expectation (XX is the correct length).
  - Other: Various error conditions.

# File Selection and FCI

One of the most complex aspects of ISO 7816 is the SELECT command (0xA4). The response to a selection depends heavily on the P2 parameter. This package abstracts this complexity via the `SelectResult` and `ParseSelectData` utilities, which handle:

  - FCP (File Control Parameters) - Tag '62'
  - FMD (File Management Data) - Tag '64'
  - FCI (File Control Information) - Tag '6F'
  - Proprietary Data - Tag 'C0' or 'A5'

# Usage Example: Analyzing a Select Response

The following example demonstrates how to interpret a raw trace from a SELECT command execution using the SelectResult wrapper.

	// Assuming 'trace' is a slice of transactions recorded during execution:
	result, err := iso7816.NewSelectResult(trace)
	if err != nil {
	    log.Fatal(err)
	}

	// 1. Check if the selection was technically successful (SW 9000)
	if result.IsSuccess() {
	    fmt.Println("Application Selected Successfully")
	}

	// 2. Parse the File Control Information (FCI)
	// This automatically handles FCP, FMD, or flat structures.
	fci, err := result.FCI()
	if err != nil {
	    log.Printf("Could not parse FCI: %v", err)
	    return
	}

	// 3. Access parsed data safely
	if aid := fci.GetAID(); aid != nil {
	    fmt.Printf("Selected AID: %X\n", aid)
	}

	if label := fci.ApplicationLabel(); label != nil {
	    fmt.Printf("Label: %s\n", string(label))
	}

	// 4. Generate a full human-readable report for debugging
	fmt.Println(result.Describe())
*/
package iso7816
