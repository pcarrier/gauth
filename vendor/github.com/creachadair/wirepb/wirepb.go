// Package wirepb implements a rudimentary decoder for the protocol buffers wire format.
//
// See: https://protobuf.dev/programming-guides/encoding
package wirepb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

//go:generate go run github.com/creachadair/enumgen@latest -output enums.go

/*enumgen:type Type
doc: Type is a protobuf wire type code.
zero: Invalid
val-doc: Values for low-level wire types.
values:
  - name: Varint
    doc: Base 128 varint
    index: 0
  - name: I64
    doc: 64-bit fixed-width integer
  - name: Len
    doc: Length-prefixed string
  - name: StartGroup
    doc: Group start marker (obsolete, unused)
  - name: EndGroup
    doc: Group end marker (obsolete, unused)
  - name: I32
    doc: 32-bit fixed-width integer
*/

// Scanner is a protocol buffer wire format lexical scanner.
type Scanner struct {
	r *bufio.Reader

	tok  Type   // current token type
	id   int    // current field ID
	data []byte // current field contents

	err error // last error
}

// NewScanner creates a new scanner that consumes input from r.
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{r: bufio.NewReader(r), id: -1}
}

// Type returns the type of the current token, or Invalid if there is not
// currently a token available.
func (s *Scanner) Type() Type { return s.tok }

// Data returns the contents of the current token in binary form, or nil if
// there is not currently a token available. The contents of the returned slice
// are only valid until the next call to Next.
func (s *Scanner) Data() []byte { return s.data }

// ID returns the field ID of the current token, or -1 if there is no token.
func (s *Scanner) ID() int { return s.id }

// Next advances s to the next token of the input or reports an error.  At the
// end of the input, Next returns io.EOF.
func (s *Scanner) Next() error {
	s.tok = Invalid
	s.id = -1
	s.data = nil
	s.err = nil

	tag, err := binary.ReadUvarint(s.r)
	if err == io.EOF {
		return s.fail(err) // return unwrapped
	} else if err != nil {
		return s.failf("read tag: %w", err)
	}
	id, wtype := tag>>3, tag&7
	switch wtype {
	case 0:
		v, err := binary.ReadUvarint(s.r)
		if err != nil {
			return s.failf("read varint: %w", err)
		}
		s.data = binary.AppendUvarint(s.data, v)
		s.tok = Varint
	case 1:
		var buf [8]byte
		if _, err := io.ReadFull(s.r, buf[:]); err != nil {
			return s.failf("read i64: %w", err)
		}
		s.data, s.tok = buf[:], I64
	case 2:
		v, err := binary.ReadUvarint(s.r)
		if err != nil {
			return s.failf("read length: %w", err)
		}
		buf := make([]byte, int(v))
		if _, err := io.ReadFull(s.r, buf); err != nil {
			return s.failf("read string: %w", err)
		}
		s.data, s.tok = buf, Len
	case 5:
		var buf [4]byte
		if _, err := io.ReadFull(s.r, buf[:]); err != nil {
			return s.failf("read i32: %w", err)
		}
		s.data, s.tok = buf[:], I32
	case 3, 4:
		return s.failf("obsolete wire type %d", wtype)
	default:
		return s.failf("invalid wire type %d", wtype)
	}
	s.id = int(id)
	return nil
}

// Err returns the last error reported by Next, or nil if none.
func (s *Scanner) Err() error { return s.err }

func (s *Scanner) fail(err error) error { s.err = err; return err }

func (s *Scanner) failf(msg string, args ...any) error { return s.fail(fmt.Errorf(msg, args...)) }
