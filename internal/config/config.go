package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the application configuration
type Config struct {
	// Server configuration
	Host string `json:"host"`
	Port int    `json:"port"`

	// OAuth2 configuration
	Issuer               string `json:"issuer"`
	AccessTokenLifetime  int    `json:"access_token_lifetime"`  // in seconds
	RefreshTokenLifetime int    `json:"refresh_token_lifetime"` // in seconds
	AuthCodeLifetime     int    `json:"auth_code_lifetime"`     // in seconds

	// Database configuration
	DatabaseURI string `json:"database_uri"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Host:                 "localhost",
		Port:                 9000,
		Issuer:               "https://authlite.example.com",
		AccessTokenLifetime:  3600,    // 1 hour
		RefreshTokenLifetime: 2592000, // 30 days
		AuthCodeLifetime:     300,     // 5 minutes
		DatabaseURI:          "file:authlite.db",
	}
}

// Load reads configuration from file or environment variables
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Check if config file exists
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "config.json"
	}

	if _, err := os.Stat(configFile); err == nil {
		file, err := os.Open(configFile)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		if err := json.NewDecoder(file).Decode(cfg); err != nil {
			return nil, err
		}
	}

	// Override with environment variables if present
	if port := os.Getenv("PORT"); port != "" {
		var p int
		if _, err := fmt.Sscanf(port, "%d", &p); err == nil {
			cfg.Port = p
		}
	}

	if host := os.Getenv("HOST"); host != "" {
		cfg.Host = host
	}

	if issuer := os.Getenv("ISSUER"); issuer != "" {
		cfg.Issuer = issuer
	}

	if dbURI := os.Getenv("DATABASE_URI"); dbURI != "" {
		cfg.DatabaseURI = dbURI
	}

	return cfg, nil
}
