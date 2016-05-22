package main

import (
	"github.com/codegangsta/cli"
	"testing"
)

const okExitCode = 0

func getMockOsExiter(t *testing.T, expectedExitCode int) func(int) {
	return func(code int) {
		if code != expectedExitCode {
			t.Fatalf("Unexpected exit code: expected %d, got %d", expectedExitCode, code)
		}
	}
}

func testMainWithArguments(t *testing.T, expectedExitCode int, args ...string) {
	cli.OsExiter = getMockOsExiter(t, expectedExitCode)

	appArgs := append([]string{"name-of-binary"}, args...)
	runApp(appArgs)
}

func TestRunMain(t *testing.T) {
	testMainWithArguments(t, okExitCode)
}

func TestProcessMailDefault(t *testing.T) {
	testMainWithArguments(t, okExitCode, "process-mail")
}

func TestProcessMailFile(t *testing.T) {
	testMainWithArguments(t, okExitCode, "process-mail", "--file", "./test/mails/plaintext.eml")
}

func TestProcessFileError(t *testing.T) {
	testMainWithArguments(t, errorExitCode, "process-mail", "--file", "./invalid")
}
