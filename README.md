# KMS Integration

This project provides integration with AWS Key Management Service (KMS) for generating and encrypting data keys.

## Features

- **Generate Data Key**: Uses AWS KMS to generate a data key, returning both plaintext and ciphertext versions.
- **Encrypt Data**: Encrypts plaintext using AES-GCM with the provided data key.

## Installation

To use this project, ensure you have Go installed and set up your AWS credentials.

```bash
go get github.com/aws/aws-sdk-go-v2
```

## Usage

### Generate Data Key

```go
keyID := "your-kms-key-id"
plaintext, ciphertext, err := GenerateDataKey(kmsClient, keyID)
if err != nil {
    // Handle error
}
```

### Encrypt Data

```go
encrypted, err := Encrypt([]byte("your-plaintext"), plaintext)
if err != nil {
    // Handle error
}
```

## Testing

To run the tests, use:

```bash
go test ./...
```

## License

This project is licensed under the MIT License.

