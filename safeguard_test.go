package safeguard

import (
	"testing"
)

const (
	encKey = "rLxcK-ApRyAAsyxZDaiQ*n2m.hF4NXD6"
)

func TestHash(t *testing.T) {
	type args struct {
		plaintext string
		hash      string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test 'Hello World'",
			args: args{
				plaintext: "Hello World",
				hash:      "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
			},
		},
		{
			name: "Test 'foobar'",
			args: args{
				plaintext: "foobar",
				hash:      "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(&Config{})

			result, err := s.Hash(tt.args.plaintext)
			if err != nil {
				t.Errorf("NewHash() error = %v", err)
			}

			if result != tt.args.hash {
				t.Errorf("NewHash() = %v, want %v", result, tt.args.hash)
			}
		})
	}
}

func TestEncrypt(t *testing.T) {
	type args struct {
		plaintext string
		key       string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test 'Hello World'",
			args: args{
				plaintext: "Hello World",
				key:       encKey,
			},
		},
		{
			name: "Test 'foobar'",
			args: args{
				plaintext: "foobar",
				key:       encKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(&Config{
				EncryptionKey: tt.args.key,
			})

			if s.Config.EncryptionKey == "" {
				t.Errorf("EncryptionKey is empty")
			}

			encryptedResult, err := s.Encrypt(tt.args.plaintext)
			if err != nil {
				t.Errorf("Encrypt() error = %v", err)
			}

			decryptedResult, err := s.Decrypt(encryptedResult)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
			}

			if decryptedResult != tt.args.plaintext {
				t.Errorf("Decrypt() = %v, want %v", decryptedResult, tt.args.plaintext)
			}

			result1, _ := s.Encrypt(tt.args.plaintext)
			result2, _ := s.Encrypt(tt.args.plaintext)

			if result1 == result2 {
				t.Errorf("Encrypt() = %v, want %v", result1, result2)
			}
		})
	}
}

func TestEncryptWithNonce(t *testing.T) {
	type args struct {
		plaintext string
		nonce     string
		key       string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test 'Hello World'",
			args: args{
				plaintext: "Hello World",
				nonce:     "123456",
				key:       encKey,
			},
		},
		{
			name: "Test 'foobar'",
			args: args{
				plaintext: "foobar",
				nonce:     "ABCDEFGHIJKLMNOPQRSTUWXYZ12345",
				key:       encKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(&Config{
				EncryptionKey: tt.args.key,
			})

			if s.Config.EncryptionKey == "" {
				t.Errorf("EncryptionKey is empty")
			}

			encryptedResult, err := s.EncryptWithNonce(tt.args.plaintext, tt.args.nonce)
			if err != nil {
				t.Errorf("EncryptWithNonce() error = %v", err)
			}

			decryptedResult, err := s.Decrypt(encryptedResult)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
			}

			if decryptedResult != tt.args.plaintext {
				t.Errorf("Decrypt() = %v, want %v", decryptedResult, tt.args.plaintext)
			}

			result1, _ := s.EncryptWithNonce(tt.args.plaintext, tt.args.nonce)
			result2, _ := s.EncryptWithNonce(tt.args.plaintext, tt.args.nonce)

			if result1 != result2 {
				t.Errorf("EncryptWithNonce() = %v, want %v", result1, result2)
			}
		})
	}
}

func TestEncryptString(t *testing.T) {
	type args struct {
		plaintext string
		key       string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test 'Hello World'",
			args: args{
				plaintext: "Hello World",
				key:       encKey,
			},
		},
		{
			name: "Test 'foobar'",
			args: args{
				plaintext: "foobar",
				key:       encKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(&Config{
				EncryptionKey: tt.args.key,
			})

			if s.Config.EncryptionKey == "" {
				t.Errorf("EncryptionKey is empty")
			}

			encryptedResult := s.EncryptString(tt.args.plaintext)

			decryptedResult := s.DecryptString(encryptedResult)

			if decryptedResult != tt.args.plaintext {
				t.Errorf("Decrypt() = %v, want %v", decryptedResult, tt.args.plaintext)
			}

			result1 := s.EncryptString(tt.args.plaintext)
			result2 := s.EncryptString(tt.args.plaintext)

			if result1 == result2 {
				t.Errorf("EncryptString() = %v, want %v", result1, result2)
			}
		})
	}
}

func TestEncryptStringWithNonce(t *testing.T) {
	type args struct {
		plaintext string
		nonce     string
		key       string
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Test 'Hello World'",
			args: args{
				plaintext: "Hello World",
				nonce:     "123456",
				key:       encKey,
			},
		},
		{
			name: "Test 'foobar'",
			args: args{
				plaintext: "foobar",
				nonce:     "ABCDEFGHIJKLMNOPQRSTUWXYZ12345",
				key:       encKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(&Config{
				EncryptionKey: tt.args.key,
			})

			if s.Config.EncryptionKey == "" {
				t.Errorf("EncryptionKey is empty")
			}

			encryptedResult := s.EncryptStringWithNonce(tt.args.plaintext, tt.args.nonce)

			decryptedResult := s.DecryptString(encryptedResult)

			if decryptedResult != tt.args.plaintext {
				t.Errorf("Decrypt() = %v, want %v", decryptedResult, tt.args.plaintext)
			}

			result1 := s.EncryptStringWithNonce(tt.args.plaintext, tt.args.nonce)
			result2 := s.EncryptStringWithNonce(tt.args.plaintext, tt.args.nonce)

			if result1 != result2 {
				t.Errorf("EncryptStringWithNonce() = %v, want %v", result1, result2)
			}
		})
	}
}

func BenchmarkHash(b *testing.B) {
	s := New(&Config{})

	for i := 0; i < b.N; i++ {
		s.Hash("Hello World")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	s := New(&Config{
		EncryptionKey: encKey,
	})

	for i := 0; i < b.N; i++ {
		s.Encrypt("Hello World")
	}
}

func BenchmarkEncryptString(b *testing.B) {
	s := New(&Config{
		EncryptionKey: encKey,
	})

	for i := 0; i < b.N; i++ {
		s.EncryptString("Hello World")
	}
}
