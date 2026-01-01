package main

import (
	"fmt"
	"log"

	"github.com/ebfe/scard"
	"github.com/gregLibert/smart-card/pkg/emv"
	"github.com/gregLibert/smart-card/pkg/iso7816"
)

func main() {
	// --- 1. Hardware Setup ---
	ctx, card := connectToCard()

	defer func() {
		if err := ctx.Release(); err != nil {
			log.Printf("Warning: Failed to release context: %v", err)
		}
	}()

	defer func() {
		if err := card.Disconnect(scard.LeaveCard); err != nil {
			log.Printf("Warning: Failed to disconnect card: %v", err)
		}
	}()

	// --- 2. Logic Setup ---
	client := iso7816.NewClient(card)
	cls, _ := iso7816.NewClass(0x00)

	// --- 3. Execution Flow ---

	// Step 1: Try to find the Payment System Environment (PSE)
	sfi, err := step1SelectPSE(client, cls)
	if err != nil {
		log.Printf("Step 1 Warning: %v", err)
		// We continue, because sometimes we might want to try manual selection later
		// even if PSE fails (though in this demo, Step 2 depends on Step 1).
	}

	// Step 2: If we found a directory (SFI), read it to find Applications (AIDs)
	var candidateAIDs [][]byte
	if sfi > 0 {
		candidateAIDs = step2ReadDirectory(client, cls, sfi)
	} else {
		fmt.Println("\n>> Step 2 Skipped: No Valid SFI found in Step 1.")
	}

	// Step 3: Select every application found
	step3SelectCandidates(client, cls, candidateAIDs)

	fmt.Println("\n>> Demo Finished Successfully")
}

// =========================================================================
// Helper Functions
// =========================================================================

// connectToCard handles the PC/SC context establishment and reader connection.
func connectToCard() (*scard.Context, *scard.Card) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Fatalf("Error establishing context: %s", err)
	}

	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		if relErr := ctx.Release(); relErr != nil {
			log.Printf("Warning: Failed to release context during error handling: %v", relErr)
		}
		log.Fatal("No smart card reader found.")
	}

	fmt.Printf(">> Using reader: %s\n", readers[0])

	// Force T=0 or T=1 to avoid "Parameter Incorrect" errors (Error 57)
	card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolT0|scard.ProtocolT1)
	if err != nil {
		if relErr := ctx.Release(); relErr != nil {
			log.Printf("Warning: Failed to release context during error handling: %v", relErr)
		}
		log.Fatalf("Error connecting to card: %s", err)
	}

	return ctx, card
}

// step1SelectPSE selects the Contact/Contactless PSE and tries to extract the SFI.
func step1SelectPSE(client *iso7816.Client, cls iso7816.Class) (byte, error) {
	fmt.Println("\n=============================================")
	fmt.Println(" Step 1: SELECT PSE (1PAY.SYS.DDF01)")
	fmt.Println("=============================================")

	pseCmd := iso7816.SelectByAID(cls, []byte("1PAY.SYS.DDF01"))
	pseTrace, err := client.Send(pseCmd)
	if err != nil {
		return 0, fmt.Errorf("transmission failed: %w", err)
	}

	pseRes, err := iso7816.NewSelectResult(pseTrace)
	if err != nil {
		return 0, fmt.Errorf("result creation failed: %w", err)
	}

	fmt.Println(pseRes.Describe())

	if !pseRes.IsSuccess() {
		return 0, fmt.Errorf("PSE selection failed with status: %s", pseRes.Last().Response.Status.Verbose())
	}

	// Parse EMV Data
	rawData := pseRes.Last().Response.Data
	fciEmv, err := emv.ParseFCI(rawData)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PSE FCI: %w", err)
	}

	fmt.Println(fciEmv.Describe())

	// Extract SFI
	if len(fciEmv.ProprietaryTemplate.SFI) > 0 {
		return fciEmv.ProprietaryTemplate.SFI[0], nil
	}

	return 0, nil
}

// step2ReadDirectory iterates over records in the SFI to find Application IDs (AIDs).
func step2ReadDirectory(client *iso7816.Client, cls iso7816.Class, sfi byte) [][]byte {
	fmt.Println("\n=============================================")
	fmt.Printf(" Step 2: EXPLORING DIRECTORY (SFI %d)\n", sfi)
	fmt.Println(" Counting records until 'Record Not Found'...")
	fmt.Println("=============================================")

	var collectedAIDs [][]byte

	// Loop strictly from 1 to 30 (max records in a file)
	for recNum := byte(1); recNum <= 30; recNum++ {
		fmt.Printf("\n[Record #%d] Querying target SFI %d...\n", recNum, sfi)

		readCmd := iso7816.ReadRecord(cls, sfi, recNum)
		readTrace, err := client.Send(readCmd)
		if err != nil {
			log.Printf("(!) Communication broken: %v", err)
			break
		}

		// Stop if we hit the end of the file (Status 6A83)
		if readTrace.Last().Response.Status == 0x6A83 {
			fmt.Printf(">> Status 6A83 received: End of Directory reached.\n")
			break
		}

		// Display Technical Report
		readRes, _ := iso7816.NewReadRecordResult(readTrace)
		fmt.Println(readRes.Describe())

		if readRes.IsSuccess() {
			// Parse EMV Business Data
			rawData := readTrace.Last().Response.Data
			fmt.Printf("   -> Found record entry (%d bytes). Parsing EMV content...\n", len(rawData))

			if record, err := emv.ParseDirectoryRecord(rawData); err == nil {
				fmt.Println(record.Describe())

				// Collect AIDs found in this record
				for _, app := range record.Applications {
					if len(app.AID) > 0 {
						fmt.Printf("      [+] Adding Candidate AID: %X (%s)\n", app.AID, app.ApplicationLabel)
						collectedAIDs = append(collectedAIDs, app.AID)
					}
				}
			} else {
				fmt.Printf("   (!) Failed to parse EMV Directory Record: %v\n", err)
			}
		}
	}

	return collectedAIDs
}

// step3SelectCandidates iterates through the list of found AIDs and selects them one by one.
func step3SelectCandidates(client *iso7816.Client, cls iso7816.Class, aids [][]byte) {
	fmt.Println("\n=============================================")
	fmt.Printf(" Step 3: SELECTING CANDIDATE APPLICATIONS (%d found)\n", len(aids))
	fmt.Println("=============================================")

	if len(aids) == 0 {
		fmt.Println(">> No Applications found to select.")
		return
	}

	for i, aid := range aids {
		fmt.Printf("\n------------------------------------------------------------\n")
		fmt.Printf(" [App %d/%d] Selecting AID: %X\n", i+1, len(aids), aid)
		fmt.Printf("------------------------------------------------------------\n")

		selectCmd := iso7816.SelectByAID(cls, aid)
		trace, err := client.Send(selectCmd)
		if err != nil {
			log.Printf("Transmission failed for AID %X: %v", aid, err)
			continue
		}

		res, _ := iso7816.NewSelectResult(trace)
		if res.IsSuccess() {
			// Try to parse the response as an EMV FCI
			rawData := res.Last().Response.Data
			if fciEmv, err := emv.ParseFCI(rawData); err == nil {
				fmt.Println(fciEmv.Describe())
			} else {
				// Fallback to generic ISO description if EMV parsing fails
				fmt.Println(res.Describe())
			}
		} else {
			fmt.Printf("Selection Failed: %s\n", res.Last().Response.Status.Verbose())
		}
	}
}
