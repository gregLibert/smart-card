package iso7816

// TRANSACTION:
// A Transaction represents the atomic unit of communication defined in ISO 7816-3:
// one Command APDU (C-APDU) sent by the terminal, followed by one Response APDU (R-APDU)
// sent back by the card.
//
// TRACE:
// A Trace is a chronological sequence of Transactions. It captures the full history of a
// logical operation. This is particularly important in ISO 7816-4 flows where a single
// logical intent (e.g., "Select File") may result in multiple physical transactions due
// to protocol mechanisms:
// 1. "61 XX" (Process Completed): The card has XX extra bytes. The terminal must send a GET RESPONSE.
// 2. "6C XX" (Wrong Length): The terminal must re-send the command with Le = XX.
//
// In these cases, the Trace contains the entire conversation, and IsSuccess() evaluates
// the final outcome.

// Transaction represents a completed Command-Response pair.
type Transaction struct {
	Command  *CommandAPDU
	Response *ResponseAPDU
}

// IsSuccess checks if the transaction ended with a successful status.
// It returns false if the response is missing.
func (t *Transaction) IsSuccess() bool {
	if t.Response == nil {
		return false
	}
	return t.Response.Status.IsSuccess()
}

// Trace is a sequence of transactions (Command-Response pairs).
// It represents the full history of a logical exchange (including 61xx/6Cxx retries).
type Trace []Transaction

// Last returns the final transaction of the trace.
// Returns nil if the trace is empty.
func (t Trace) Last() *Transaction {
	if len(t) == 0 {
		return nil
	}
	return &t[len(t)-1]
}

// IsSuccess checks if the FINAL transaction in the trace was successful.
// This determines if the overall logical operation succeeded, regardless of
// intermediate warnings (like 61XX) in previous transactions.
func (t Trace) IsSuccess() bool {
	last := t.Last()
	if last == nil {
		return false
	}
	return last.IsSuccess()
}
