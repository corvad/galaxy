package concorde

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/pem"
	"io"
	"log"
	"os"
)

type Concorde struct {
	encapsulationKey *mlkem.EncapsulationKey1024
	decapsulationKey *mlkem.DecapsulationKey1024
	secret           []byte
}

func New() Concorde {
	decapsulationKey, err := mlkem.GenerateKey1024()
	if err != nil {
		log.Fatal(err)
	}
	encapsulationKey := decapsulationKey.EncapsulationKey()
	return Concorde{encapsulationKey, decapsulationKey, []byte{}}
}

func (c *Concorde) AcceptCipheredSecret(ciphertext []byte) {
	secret, err := c.decapsulationKey.Decapsulate(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	c.secret = secret
}

func (c *Concorde) GenerateCipheredSecret(encapsulationKey []byte) []byte {
	tmpEncapsulationKey, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
	if err != nil {
		log.Fatal(err)
	}
	secret, ciphertext := tmpEncapsulationKey.Encapsulate()
	c.secret = secret
	return ciphertext
}

func NewFromFile(filename string) Concorde {
	file, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	block, rest := pem.Decode(file)
	_ = rest
	if block == nil || block.Type != "ML-KEM-1024 PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing private key")
	}
	decapsulationKey, err := mlkem.NewDecapsulationKey1024(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	encapsulationKey := decapsulationKey.EncapsulationKey()
	return Concorde{encapsulationKey, decapsulationKey, []byte{}}
}

func (c *Concorde) ExportDecapsulationKeyToFile(filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	block := &pem.Block{
		Type:  "ML-KEM-1024 PRIVATE KEY",
		Bytes: c.GetDecapsulationKey(),
	}
	if err := pem.Encode(file, block); err != nil {
		log.Fatal(err)
	}
}

func (c *Concorde) ExportEncapsulationKeyToFile(filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	block := &pem.Block{
		Type:  "ML-KEM-1024 PUBLIC KEY",
		Bytes: c.GetEncapsulationKey(),
	}
	if err := pem.Encode(file, block); err != nil {
		log.Fatal(err)
	}
}

func (c *Concorde) AES256Encrypt(plaintext []byte) []byte {
	block, err := aes.NewCipher(c.secret)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

func (c *Concorde) AES256Decrypt(ciphertext []byte) []byte {
	block, err := aes.NewCipher(c.secret)
	if err != nil {
		log.Fatal(err)
	}
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	return plaintext
}


func (c *Concorde) GetEncapsulationKey() []byte {
	return c.encapsulationKey.Bytes()
}

func (c *Concorde) GetSharedSecret() []byte {
	return c.secret
}

func (c *Concorde) GetDecapsulationKey() []byte {
	return c.decapsulationKey.Bytes()
}