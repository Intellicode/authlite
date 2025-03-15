// filepath: /Users/tom/GitHub/authlite/scripts/generate_keys.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	// Create keys directory if it doesn't exist
	keysDir := filepath.Join("..", "keys")
	if _, err := os.Stat(keysDir); os.IsNotExist(err) {
		if err := os.MkdirAll(keysDir, 0755); err != nil {
			log.Fatalf("Failed to create keys directory: %v", err)
		}
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Encode private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyPath := filepath.Join(keysDir, "private_key.pem")
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		log.Fatalf("Failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		log.Fatalf("Failed to write private key to file: %v", err)
	}

	// Encode public key to PEM format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	}

	publicKeyPath := filepath.Join(keysDir, "public_key.pem")
	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		log.Fatalf("Failed to create public key file: %v", err)
	}
	defer publicKeyFile.Close()

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		log.Fatalf("Failed to write public key to file: %v", err)
	}

	fmt.Printf("RSA key pair generated successfully:\n")
	fmt.Printf("- Private key: %s\n", privateKeyPath)
	fmt.Printf("- Public key: %s\n", publicKeyPath)
	fmt.Println("Use these keys with the OIDC provider for signing ID tokens.")
}