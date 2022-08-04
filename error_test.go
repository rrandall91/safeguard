package safeguard

import (
	"testing"
)

func TestError(t *testing.T) {
	tests := []struct {
		name string
		arg  string
	}{
		{
			name: "Test 'Hello World'",
			arg:  "Hello World",
		},
		{
			name: "Test 'foobar'",
			arg:  "foobar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Error(tt.arg)
			if err.Error() != tt.arg {
				t.Error("Error() failed")
			}
		})
	}
}
