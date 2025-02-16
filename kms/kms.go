package kmstest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// Define EncryptFunc and DecryptFunc variables for easier mocking
var EncryptFunc = Encrypt
var DecryptFunc = Decrypt

// KMSClient interface for mocking
type KMSClient interface {
	GenerateDataKey(ctx context.Context, input *kms.GenerateDataKeyInput, opts ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

func GenerateDataKey(kmsClient KMSClient, keyID string) ([]byte, []byte, error) {
	input := &kms.GenerateDataKeyInput{
		KeyId:   &keyID,
		KeySpec: "AES_256",
	}

	result, err := kmsClient.GenerateDataKey(context.TODO(), input)
	if err != nil {
		return nil, nil, err
	}

	return result.Plaintext, result.CiphertextBlob, nil
}

func Encrypt(plaintext, dataKey []byte) (string, error) {
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(ciphertextBase64 string, dataKey []byte) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	plaintext, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
