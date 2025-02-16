package service

func HandleSecureData(kmsClient kmstest.KMSClient, keyID string, data []byte) (string, error) {
	key, _, err := kmstest.GenerateDataKey(kmsClient, keyID)
	if err != nil {
		return "", err
	}

	encryptedData, err := kmstest.EncryptFunc(data, key)
	if err != nil {
		return "", err
	}

	decryptedData, err := kmstest.DecryptFunc(encryptedData, key)
	if err != nil {
		return "", err
	}

	return string(decryptedData), nil
}
