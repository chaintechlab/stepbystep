package main

import (
	"crypto/sha256"
)

func Hash(input []byte) [32]byte {
	sum := sha256.Sum256(input)
	return sha256.Sum256(sum[:])
}
