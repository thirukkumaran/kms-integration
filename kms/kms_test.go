package kmstest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// MockKMSClient directly mocks the KMS Client
type MockKMSClient struct{}

func (m *MockKMSClient) GenerateDataKey(ctx context.Context, input *kms.GenerateDataKeyInput, opts ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if input.KeyId == nil || *input.KeyId == "" {
		return nil, errors.New("KeyId is required")
	}

	return &kms.GenerateDataKeyOutput{
		Plaintext:      make([]byte, 32),         // Mock key
		CiphertextBlob: []byte("mockCiphertext"), // Mock encrypted key
	}, nil
}

// Test for GenerateDataKey
func TestGenerateDataKey(t *testing.T) {
	mockClient := &MockKMSClient{}
	keyID := "mock-key-id"

	// Simulating the real function
	input := &kms.GenerateDataKeyInput{
		KeyId:   &keyID,
		KeySpec: "AES_256",
	}

	result, err := mockClient.GenerateDataKey(context.TODO(), input)
	if err != nil {
		t.Fatalf("Failed to generate data key: %v", err)
	}

	if len(result.Plaintext) != 32 {
		t.Errorf("Expected plaintext length 32, got %d", len(result.Plaintext))
	}

	if string(result.CiphertextBlob) != "mockCiphertext" {
		t.Errorf("Unexpected ciphertext blob. Got %s, want %s", result.CiphertextBlob, "mockCiphertext")
	}
}

// Test for encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	testDataKey := make([]byte, 32) // Mock AES-256 key
	plaintext := "Test Encryption"

	ciphertext, err := Encrypt([]byte(plaintext), testDataKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedText, err := Decrypt(ciphertext, testDataKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decryptedText != plaintext {
		t.Errorf("Decrypted text does not match original. Got %s, want %s", decryptedText, plaintext)
	}
}

// Test encryption error with an invalid key
func TestEncryptError(t *testing.T) {
	invalidKey := make([]byte, 15) // Invalid key size
	_, err := Encrypt([]byte("Test"), invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key size, got none")
	}
}

// Test decryption error with invalid ciphertext
func TestDecryptError(t *testing.T) {
	validKey := make([]byte, 32)
	_, err := Decrypt("invalidciphertext", validKey)
	if err == nil {
		t.Error("Expected error for invalid ciphertext, got none")
	}
}
