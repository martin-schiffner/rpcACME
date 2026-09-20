package controllers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"rpcca/acme/config"

	fiberlog "github.com/gofiber/fiber/v3/log"
)

const (
	NonceSize     = 12
	AcmeNonceSize = 16
)

type CryptoService interface {
	EncryptSecret(secret []byte) (string, error)
	DecryptSecret(cipherText string) ([]byte, error)
	AcmeNonce() string
	RandomStringB64(length int) string
}

type cryptoService struct {
	symmetricKey string
}

func NewCryptoService(cfg config.Config) CryptoService {
	return &cryptoService{
		symmetricKey: cfg.EncryptionKey,
	}
}

func (c *cryptoService) EncryptSecret(secret []byte) (string, error) {
	key, err := hex.DecodeString(c.symmetricKey)
	if err != nil {
		fiberlog.Errorf("hex-decoding encryption key failed: %s", err.Error())
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fiberlog.Errorf("error encrypting secret: %s", err.Error())
		return "", err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fiberlog.Errorf("error encrypting secret: %s", err.Error())
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fiberlog.Errorf("error encrypting secret: %s", err.Error())
		return "", err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, secret, nil)
	cipherB64 := base64.StdEncoding.EncodeToString(ciphertext)
	return cipherB64, nil
}

func (c *cryptoService) DecryptSecret(cipherText string) ([]byte, error) {
	key, err := hex.DecodeString(c.symmetricKey)
	if err != nil {
		fiberlog.Errorf("hex-decoding encryption key failed: %s", err.Error())
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fiberlog.Errorf("error decrypting secret: %s", err.Error())
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		fiberlog.Errorf("error decrypting secret: %s", err.Error())
		return nil, err
	}

	cypherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		fiberlog.Errorf("error decrypting secret: %s", err.Error())
		return nil, err
	}

	if len(cypherBytes) <= NonceSize {
		fiberlog.Errorf("given ciphertext too short: %d bytes", len(cypherBytes))
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciph := cypherBytes[:NonceSize], cypherBytes[NonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciph, nil)
	if err != nil {
		fiberlog.Errorf("error decrypting secret: %s", err.Error())
		return nil, err
	}

	return plaintext, nil
}

func (c *cryptoService) AcmeNonce() string {
	nonce := make([]byte, AcmeNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fiberlog.Errorf("error generating ACME nonce: %s", err.Error())
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(nonce)
}

func (c *cryptoService) RandomStringB64(length int) string {
	randString := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, randString); err != nil {
		fiberlog.Errorf("error generating random string: %s", err.Error())
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(randString)
}
