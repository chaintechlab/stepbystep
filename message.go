package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	MainNet  = 0xD9B4BEF9
	TestNet  = 0xDAB5BFFA
	TestNet3 = 0x0709110B
)

var (
	CurrentMagic uint32
)

const (
	HeaderLength     = 24
	MaxMessageLength = 1000 * 1000 * 1000
)

type MessageHeader struct {
	Magic    uint32
	Cmd      string
	Len      uint32
	Checksum []byte
}

func (h *MessageHeader) Marshal() []byte {
	output := make([]byte, HeaderLength)
	binary.BigEndian.PutUint32(output, h.Magic)
	copy(output[4:16], []byte(h.Cmd))
	binary.BigEndian.PutUint32(output[16:20], h.Len)
	copy(output[20:24], h.Checksum)
	return output
}

func bytesToString(input []byte) string {
	index := bytes.IndexByte(input, 0)
	if index == -1 {
		return string(input)
	}
	return string(input[0:index])
}

func (h *MessageHeader) Unmarshal(input []byte) error {
	if len(input) != HeaderLength {
		return errors.New("invalid_header_length")
	}
	h.Magic = binary.BigEndian.Uint32(input)
	h.Cmd = bytesToString(input[4:16])
	h.Len = binary.BigEndian.Uint32(input[16:20])
	h.Checksum = input[20:24]
	return h.validate()
}

func (h *MessageHeader) validate() error {
	if h.Magic != CurrentMagic {
		return errors.New("invalid_magic")
	}
	if len(h.Cmd) > 12 {
		return errors.New("invalid_cmd")
	}
	if h.Len > MaxMessageLength {
		return errors.New("invalid_message_length")
	}
	return nil
}

type Message struct {
	Header  MessageHeader
	Payload []byte
}

func NewMessage(cmd string, payload []byte) (*Message, error) {
	if len(cmd) > 12 {
		return nil, errors.New("invalid_cmd")
	}
	if len(payload) > MaxMessageLength {
		return nil, errors.New("invalid_message_length")
	}
	h := DoubleSha256(payload)
	return &Message{
		Header: MessageHeader{
			Magic:    CurrentMagic,
			Cmd:      cmd,
			Len:      uint32(len(payload)),
			Checksum: h[0:4],
		},
		Payload: payload,
	}, nil
}

func (m *Message) validate() error {
	hash := DoubleSha256(m.Payload)
	for i := 0; i < 4; i++ {
		if m.Header.Checksum[i] != hash[i] {
			return errors.New("invalid hash")
		}
	}
	return nil
}

func (m *Message) WriteTo(w io.Writer) (n int, err error) {
	output := m.Header.Marshal()
	n, err = w.Write(output)
	if err != nil {
		return n, err
	}
	l, err := w.Write(m.Payload)
	return n + l, err
}

func (m *Message) ReadFrom(r io.Reader) (err error) {
	input := make([]byte, HeaderLength)
	_, err = io.ReadFull(r, input)
	if err != nil {
		return err
	}
	err = m.Header.Unmarshal(input)
	if err != nil {
		return err
	}
	m.Payload = make([]byte, int(m.Header.Len))
	_, err = io.ReadFull(r, m.Payload)
	if err != nil {
		return err
	}
	return m.validate()
}
