package iso7816

import (
	"fmt"
)

// CLIENT & PROTOCOL LOGIC:
// The Client acts as a high-level driver over the physical connection.
// It implements the automatic handling of ISO 7816-3 transport behaviors that are
// often exposed to the application layer in T=0 protocols:
//
// 1. "61 XX" (Response Available):
//    The card indicates that XX bytes are waiting. The client automatically generates
//    and sends a GET RESPONSE command to retrieve them.
//
// 2. "6C XX" (Wrong Length):
//    The card indicates that the expected length (Le) was incorrect and suggests XX.
//    The client automatically re-sends the original command with Le = XX.
//
// The Send() method returns a Trace, which is a log of all atomic transactions
// occurred to fulfill the logical request.

// Transmitter abstracts the physical card connection.
type Transmitter interface {
	Transmit(cmd []byte) ([]byte, error)
}

// Client manages the high-level communication with the card.
type Client struct {
	Card Transmitter
}

// NewClient creates a new Client instance.
func NewClient(card Transmitter) *Client {
	return &Client{Card: card}
}

// Send transmits a command and handles protocol logic (61xx, 6Cxx).
func (c *Client) Send(cmd *CommandAPDU) (Trace, error) {
	rawCmd, err := cmd.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding error: %w", err)
	}

	rawResp, err := c.Card.Transmit(rawCmd)
	if err != nil {
		return nil, fmt.Errorf("transmission error: %w", err)
	}

	resp, err := ParseResponseAPDU(rawResp)
	if err != nil {
		return nil, err
	}

	currentTx := Transaction{
		Command:  cmd,
		Response: resp,
	}

	trace := Trace{currentTx}

	sw1 := resp.Status.SW1()
	sw2 := resp.Status.SW2()

	// Case 61XX: More data available -> Issue GET RESPONSE
	if sw1 == 0x61 {
		// ISO 7816-4: GET RESPONSE must use the same logical channel as the original command.
		respCls := cmd.Class
		respCls.IsChained = false

		ins, _ := NewInstruction(INS_GET_RESPONSE)

		// Le = sw2 (number of bytes available)
		getRespCmd := NewCommandAPDU(respCls, ins, 0x00, 0x00, nil, int(sw2))

		subTrace, err := c.Send(getRespCmd)
		if err != nil {
			return trace, err
		}

		trace = append(trace, subTrace...)
		return trace, nil
	}

	// Case 6CXX: Wrong Length -> Re-issue original command with correct Le
	if sw1 == 0x6C {
		// Clone command to update Le without mutating the original pointer
		newCmd := *cmd
		newCmd.Ne = int(sw2)

		subTrace, err := c.Send(&newCmd)
		if err != nil {
			return trace, err
		}

		trace = append(trace, subTrace...)
		return trace, nil
	}

	return trace, nil
}
