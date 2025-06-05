package utils

import (
	"testing"
)

func TestChunkString(t *testing.T) {
	originalText := "abcdefghijklmnopqrstuvwxyz"

	chunks := ChunkString(originalText, 10)

	if len(chunks) != 3 {
		t.Fail()
	}

	value := ""

	for i := 0; i < len(chunks); i++ {
		value += chunks[i]
	}

	if value != originalText {
		t.Fail()
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"
	originalText := "hello"

	encrypted, err := Encrypt(originalText, secret)
	if err != nil {
		t.Fail()
	}

	decrypted, err := Decrypt(encrypted, secret)
	if err != nil {
		t.Fail()
	}

	if decrypted != originalText {
		t.Fail()
	}
}

func TestDecryptEmptyString(t *testing.T) {
	secret := "MLFs4TT99kOOq8h3UAVRtYoCTDYXiRcZ"

	_, err := Decrypt("", secret)

	// Must return an error
	if err == nil {
		t.Fail()
	}
}
