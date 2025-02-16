package main

import (
	"context"
	"fmt"
	"log"

	"go-kms-test/service"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

func main() {
	// Load AWS Config
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}

	// Initialize AWS KMS Client
	kmsClient := kms.NewFromConfig(cfg)

	// Sample data
	data := []byte("Sensitive Production Data")
	keyID := "your-kms-key-id"

	// Secure data processing
	result, err := service.HandleSecureData(kmsClient, keyID, data)
	if err != nil {
		log.Fatalf("HandleSecureData failed: %v", err)
	}

	fmt.Printf("Decrypted Data: %s\n", result)
}
