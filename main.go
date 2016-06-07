package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/TNG/gpg-validation-server/gpg"
	"github.com/TNG/gpg-validation-server/storage"
	"github.com/codegangsta/cli"
)

const (
	okExitCode    = 0
	errorExitCode = 1
)

var store storage.GetSetDeleter

func initGpgUtil(c *cli.Context) (*gpg.GPG, error) {
	privateKeyPath := c.String("private-key")
	if privateKeyPath == "" {
		return nil, fmt.Errorf("Invalid private key file path: %s", privateKeyPath)
	}
	privateKeyInput, err := os.Open(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot open private key file '%s': %s", privateKeyPath, err)
	}
	defer func() { _ = privateKeyInput.Close() }()

	return gpg.NewGPG(privateKeyInput, c.String("passphrase"))
}

func appAction(c *cli.Context) error {
	store = storage.NewMemoryStore()
	smtpHost := fmt.Sprintf("%v:%v", c.String("host"), c.Int("smtp-port"))
	httpHost := fmt.Sprintf("%v:%v", c.String("host"), c.Int("http-port"))

	gpgUtil, err := initGpgUtil(c)
	if err != nil {
		return fmt.Errorf("Cannot initialize GPG: %s", err)
	}

	log.Println("Setting up SMTP server listening at: ", smtpHost)
	go serveSMTPRequestReceiver(fmt.Sprintf("%v:%v", c.String("host"), c.Int("smtp-port")), gpgUtil)

	log.Println("Setting up HTTP server listening at: ", httpHost)
	log.Fatal(serveNonceConfirmer(c.String("host") + ":8080"))
	return nil
}

func processMailAction(c *cli.Context) error {
	var err error
	var inputMail *os.File

	inputFilePath := c.String("file")

	if inputFilePath == "" {
		inputMail = os.Stdin
	} else {
		inputMail, err = os.Open(inputFilePath)
		if err != nil {
			return fmt.Errorf("Cannot open mail file '%s': %s", inputFilePath, err)
		}
		defer func() { _ = inputMail.Close() }()
	}

	gpgUtil, err := initGpgUtil(c)

	processMail := getIncomingMailHandler(gpgUtil)
	processMail(inputMail)

	return nil
}

func confirmNonceAction(c *cli.Context) error {
	var nonce [32]byte

	nonceSlice, err := hex.DecodeString(c.String("nonce"))
	if err != nil {
		return err
	}
	if len(nonceSlice) != 32 {
		return errors.New(fmt.Sprint("Nonce has invalid length: ", len(nonceSlice)))
	}
	copy(nonce[:], nonceSlice)

	return ConfirmNonce(nonce)
}

func cliErrorHandler(action func(*cli.Context) error) func(*cli.Context) cli.ExitCoder {
	return func(c *cli.Context) cli.ExitCoder {
		if err := action(c); err != nil {
			return cli.NewExitError(fmt.Sprint("Error: ", err), errorExitCode)
		}
		return nil
	}
}

// subCommands to execute single aspects of the key validation process without requiring the full server startup.
var subCommands = []cli.Command{
	{
		Name:   "process-mail",
		Usage:  "process an incoming email",
		Action: cliErrorHandler(processMailAction),
		Flags: append(
			[]cli.Flag{
				cli.StringFlag{
					Name:  "file",
					Value: "./test/mails/signed_request_enigmail.eml",
					// TODO Handle missing value, use better default
					Usage: "`FILE_PATH` of the mail file, omit to read from stdin",
				},
			},
			privateKeyFlags...,
		),
	},
	{
		Name:   "confirm-nonce",
		Usage:  "process an nonce that has been confirmed",
		Action: cliErrorHandler(confirmNonceAction),
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "nonce",
				Value: "",
				Usage: "String value of the Nonce",
			},
		},
	},
}

var privateKeyFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "private-key",
		Value: "./test/keys/test-gpg-validation@server.local (0x87144E5E) sec.asc.gpg",
		// TODO Handle missing value, use better default
		Usage: "`PRIVATE_KEY_PATH` to the private gpg key of the server",
	},
	cli.StringFlag{
		Name:  "passphrase",
		Value: "validation",
		// TODO Handle missing value, use better default.
		Usage: "`PASSPHRASE` of the private key",
	},
}

// RunApp starts the server with the provided arguments.
func RunApp(args []string) {
	app := cli.NewApp()
	app.Name = "GPG Validation Service"
	app.Usage = "Run a server that manages email verification and signs verified keys with the servers GPG key."
	app.Commands = subCommands
	app.Action = cliErrorHandler(appAction)
	app.Flags = append(
		[]cli.Flag{
			cli.StringFlag{
				Name:  "host",
				Value: "localhost",
				Usage: "`HOST` of the mail and http servers. Set to the blank value to bind to all interfaces.",
			},
			cli.IntFlag{
				Name:  "http-port",
				Value: 8080,
				Usage: "`PORT` for the HTTP nonce receiver",
			},
			cli.IntFlag{
				Name:  "smtp-port",
				Value: 2525,
				Usage: "`PORT` for the SMTP server",
			},
		},
		privateKeyFlags...,
	)

	if err := app.Run(args); err != nil {
		cli.OsExiter(errorExitCode)
	} else {
		cli.OsExiter(okExitCode)
	}
}

func main() {
	RunApp(os.Args)
}
