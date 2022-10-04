package safeguard

type Config struct {
	EncryptionKey string
}

func (c *Config) Validate() error {
	if c.EncryptionKey == "" {
		return Error("encryption key is empty")
	}

	if len(c.EncryptionKey) != 16 && len(c.EncryptionKey) != 24 && len(c.EncryptionKey) != 32 {
		return Error("invalid encryption key")
	}

	return nil
}
