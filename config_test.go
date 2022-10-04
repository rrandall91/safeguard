package safeguard

import (
	"testing"
)

func TestValidate(t *testing.T) {
	type args struct {
		c *Config
	}
	tests := []struct {
		name string
		args args
		want error
	}{
		{
			name: "Test empty encryption key",
			args: args{
				c: &Config{},
			},
			want: ErrEncryptionKeyEmpty,
		},
		{
			name: "Test valid encryption key",
			args: args{
				c: &Config{
					EncryptionKey: "rLxcK-ApRyAAsyxZDaiQ*n2m.hF4NXD6",
				},
			},
			want: nil,
		},
		{
			name: "Test invalid encryption key (16 bytes)",
			args: args{
				c: &Config{
					EncryptionKey: "secret",
				},
			},
			want: ErrInvalidEncryptionKey,
		},
		{
			name: "Test invalid encryption key (24 bytes)",
			args: args{
				c: &Config{
					EncryptionKey: "secretpasswordnotgood",
				},
			},
			want: ErrInvalidEncryptionKey,
		},
		{
			name: "Test invalid encryption key (32 bytes)",
			args: args{
				c: &Config{
					EncryptionKey: "secretsecretpasswordnotgoodevennow",
				},
			},
			want: ErrInvalidEncryptionKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.c.Validate(); got != tt.want {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}
