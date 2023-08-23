package util

import (
	"encoding/hex"
	"github.com/google/uuid"
	"golang.org/x/crypto/blake2b"
)

// Generate an UUID-v4 string without hyphen.
func Uuid() (id_text string) {
	id_binary, _ := uuid.New().MarshalBinary()
	id_text = hex.EncodeToString(id_binary)
	return
}

func Blake2b(data []byte) []byte {
	digest := blake2b.Sum256(data)
	return digest[:]
}
