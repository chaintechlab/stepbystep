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

const (
	HeaderLength     = 24
	MaxMessageLength = 1000 * 1000 * 1000
)

type Message struct {
	Magic    uint32
	Cmd      string
	Len      uint32
	Checksum []byte
	Payload  []byte
}

func (m *Message) Validate() error {
	if len(m.Cmd) > 12 {
		return errors.New("invalid cmd")
	}
	if m.Len != 0 && int(m.Len) != len(m.Payload) {
		return errors.New("invalid len")
	}
	if m.Len == 0 {
		m.Len = uint32(len(m.Payload))
	}
	hash := Hash(m.Payload)
	if m.Checksum != nil {
		for i := 0; i < 4; i++ {
			if m.Checksum[i] != hash[i] {
				return errors.New("invalid hash")
			}
		}
	} else {
		copy(m.Checksum, hash[:4])
	}
	return nil
}

func (m *Message) WriteTo(w io.Writer) (n int, err error) {
	if err := m.Validate(); err != nil {
		return 0, err
	}
	output := make([]byte, HeaderLength)
	binary.BigEndian.PutUint32(output, m.Magic)
	copy(output[4:16], []byte(m.Cmd))
	binary.BigEndian.PutUint32(output[16:20], m.Len)
	copy(output[20:24], m.Checksum)
	n, err = w.Write(output)
	if err != nil {
		return n, err
	}
	l, err := w.Write(m.Payload)
	return n + l, err
}

func (m *Message) ReadFrom(r io.Reader) (err error) {
	err = binary.Read(r, binary.BigEndian, &m.Magic)
	if err != nil {
		return err
	}
	cmdBytes := make([]byte, 12)
	_, err = io.ReadFull(r, cmdBytes)
	if err != nil {
		return err
	}
	index := bytes.IndexByte(cmdBytes, 0)
	if index > 0 {
		m.Cmd = string(cmdBytes[0:index])
	} else if index == -1 {
		m.Cmd = string(cmdBytes)
	} else {
		return errors.New("invalid cmd")
	}
	err = binary.Read(r, binary.BigEndian, &m.Len)
	if err != nil {
		return err
	}
	if m.Len > MaxMessageLength {
		return errors.New("message is too long")
	}
	_, err = io.ReadFull(r, m.Checksum)
	if err != nil {
		return err
	}
	m.Payload = make([]byte, int(m.Len))
	_, err = io.ReadFull(r, m.Payload)
	return err
}
