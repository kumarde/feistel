package feistel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	log "github.com/sirupsen/logrus"
)

const ROUNDS = 16
const BLOCK_SIZE = 8

type FeistelCipher struct {
	keys [][]byte
}

func New() *FeistelCipher {
	keys := generateKeys()
	f := FeistelCipher{keys: keys}
	return &f
}

func generateRandomKey(numBytes int) ([]byte, error) {
	key := make([]byte, numBytes)
	_, err := rand.Read(key)

	if err != nil {
		return nil, err
	}
	return key, nil
}

func encryptBlock(block []byte, keys [][]byte) []byte {
	l := block[:BLOCK_SIZE/2]
	r := block[BLOCK_SIZE/2:]

	for i := 1; i < ROUNDS; i++ {
		l, r = r, roundFunc(l, r, keys[i])
	}

	return append(l, r...)
}

func decryptBlock(block []byte, keys [][]byte) []byte {
	l := block[:BLOCK_SIZE/2]
	r := block[BLOCK_SIZE/2:]

	for i := ROUNDS - 1; i > 0; i-- {
		r, l = l, roundFunc(r, l, keys[i])
	}
	return append(l, r...)
}

func roundFunc(l []byte, r []byte, key []byte) []byte {
	hmacObj := hmac.New(sha256.New, key)
	hmacObj.Write(r)
	hmacSum := hmacObj.Sum(nil)[:4]
	return xorByteArrays(l, hmacSum)
}

func xorByteArrays(a []byte, b []byte) []byte {
	if len(a) != len(b) {
		log.Errorf("Length of arrays are not the same.")
	}
	out := make([]byte, len(a))
	for i, _ := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func pad(msg []byte) []byte {
	msgLength := len(msg)
	max := BLOCK_SIZE
	for msgLength%BLOCK_SIZE != 0 {
		msg = append(msg, byte(max))
		msgLength = len(msg)
		max--
	}
	return msg
}

func stripPadding(msg []byte) []byte {
	paddingLength := BLOCK_SIZE + 1 - msg[len(msg)-1]
	messageLength := len(msg) - int(paddingLength)
	return msg[:messageLength]
}

func generateKeys() [][]byte {
	out := make([][]byte, ROUNDS)
	for i := 0; i < ROUNDS; i++ {
		key, err := generateRandomKey(64)
		if err != nil {
			log.Fatalf("could not generate a random key.")
		}
		out[i] = key
	}
	return out
}

func (f *FeistelCipher) Encrypt(msg []byte) []byte {
	paddedMsg := pad(msg)
	out := make([]byte, len(paddedMsg))
	for i := 0; i < len(paddedMsg); i += BLOCK_SIZE {
		msgBlock := paddedMsg[i : i+BLOCK_SIZE]
		encryptedBlock := encryptBlock(msgBlock, f.keys)
		for j := 0; j < BLOCK_SIZE; j++ {
			out[i+j] = encryptedBlock[j]
		}
	}
	return out
}

func (f *FeistelCipher) Decrypt(msg []byte) []byte {
	out := make([]byte, len(msg))
	for i := 0; i < len(msg); i += BLOCK_SIZE {
		msgBlock := msg[i : i+BLOCK_SIZE]
		decryptedBlock := decryptBlock(msgBlock, f.keys)
		for j := 0; j < BLOCK_SIZE; j++ {
			out[i+j] = decryptedBlock[j]
		}
	}
	return stripPadding(out)
}
