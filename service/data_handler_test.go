package service

import (
	"context"
	"errors"
	"testing"

	kms "go-kms-test/kmstest"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// MockKMSClient implements the AWS KMS Client interface for testing
type MockKMSClient struct{}

func (m *MockKMSClient) GenerateDataKey(ctx context.Context, input *kms.GenerateDataKeyInput, opts ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if input.KeyId == nil || *input.KeyId == "" {
		return nil, errors.New("KeyId is required")
	}
	return &kms.GenerateDataKeyOutput{
		Plaintext:      make([]byte, 32),
		CiphertextBlob: []byte("mockCiphertext"),
	}, nil
}

// Unit test for HandleSecureData
// Unit test for HandleSecureData
func TestHandleSecureData(t *testing.T) {
	mockClient := &MockKMSClient{}
	keyID := "mock-key-id"
	data := []byte("Sensitive Info")

	result, err := HandleSecureData(mockClient, keyID, data)
	if err != nil {
		t.Fatalf("HandleSecureData failed: %v", err)
	}

	if result != string(data) {
		t.Errorf("Expected %s, got %s", data, result)
	}
}

// Test error handling for empty KeyID
func TestHandleSecureData_MissingKeyID(t *testing.T) {
	mockClient := &MockKMSClient{}
	keyID := ""
	data := []byte("Sensitive Info")

	_, err := HandleSecureData(mockClient, keyID, data)
	if err == nil {
		t.Fatal("Expected error for missing KeyId, got none")
	}
}

// Test error handling for encryption failure
func TestHandleSecureData_EncryptError(t *testing.T) {
	mockClient := &MockKMSClient{}
	keyID := "mock-key-id"
	data := []byte("Sensitive Info")

	// Simulate encryption error
	originalEncrypt := kmstest.EncryptFunc
	defer func() { kmstest.EncryptFunc = originalEncrypt }()

	kmstest.EncryptFunc = func(data, key []byte) (string, error) {
		return "", errors.New("encryption failed")
	}

	_, err := HandleSecureData(mockClient, keyID, data)
	if err == nil || err.Error() != "encryption failed" {
		t.Fatalf("Expected encryption error, got %v", err)
	}
}

// Test error handling for decryption failure
func TestHandleSecureData_DecryptError(t *testing.T) {
	mockClient := &MockKMSClient{}
	keyID := "mock-key-id"
	data := []byte("Sensitive Info")

	// Simulate decryption error
	originalDecrypt := kmstest.DecryptFunc
	defer func() { kmstest.DecryptFunc = originalDecrypt }()

	kmstest.DecryptFunc = func(ciphertextBase64 string, dataKey []byte) (string, error) {
		return "", errors.New("decryption failed")
	}

	_, err := HandleSecureData(mockClient, keyID, data)
	if err == nil || err.Error() != "decryption failed" {
		t.Fatalf("Expected decryption error, got %v", err)
	}
}
