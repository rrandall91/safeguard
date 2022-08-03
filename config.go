package safeguard

type Config struct {
	EncryptionKey string
}

func (c *Config) Validate() error {
	if c.EncryptionKey == "" {
		return Error("encryption key is empty")
	}

	return nil
}
