// Package utils provides helper functions for tests.
package utils

import (
	"os"
	"testing"
)

// Open wraps os.Open() to reduce error handling boilerplate code.
func Open(t *testing.T, path string) (file *os.File, cleanup func()) {
	file, err := os.Open(path)

	if err != nil {
		t.Fatal("Failed to open file:", path)
	}

	cleanup = func() {
		_ = file.Close()
	}

	return
}
