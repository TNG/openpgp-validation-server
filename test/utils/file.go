// Package utils provides helper functions for tests.
package utils

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

// Open wraps os.Open() to reduce error handling boilerplate code.
func Open(t *testing.T, path string) (file *os.File, cleanup func()) {
	file, err := os.Open(path)

	require.NoError(t, err, "Failed to open file:", path)

	cleanup = func() {
		err = file.Close()
		if err != nil {
			panic(err)
		}
	}

	return
}
