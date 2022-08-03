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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.args.c.Validate(); got != tt.want {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}
