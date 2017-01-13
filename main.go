package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"

	"github.com/TNG/openpgp-validation-server/gpg"
	"github.com/TNG/openpgp-validation-server/smtp"
	"github.com/TNG/openpgp-validation-server/storage"
	"github.com/TNG/openpgp-validation-server/validator"
	"github.com/urfave/cli"
)

const (
	okExitCode    = 0
	errorExitCode = 1
)

var (
	gpgUtil    *gpg.GPG              // This service is mandatory.
	store      storage.GetSetDeleter // This service is optional, when not available no data will be stored.
	mailSender smtp.MailSender       // This service is optional, when not available no outgoing mail will be sent.
)

var smtpMailFrom string

func initGpgUtil(c *cli.Context) error {
	privateKeyPath := c.String("private-key")
	if privateKeyPath == "" {
		return fmt.Errorf("Invalid private key file path: %s", privateKeyPath)
	}
	privateKeyInput, err := os.Open(privateKeyPath)
	if err != nil {
		return fmt.Errorf("Cannot open private key file '%s': %s", privateKeyPath, err)
	}
	defer func() {
		err = privateKeyInput.Close()
		if err != nil {
			log.Fatalf("Close of private key file '%s' failed: %s", privateKeyPath, err)
		}
	}()

	util, err := gpg.NewGPG(privateKeyInput, c.String("passphrase"))
	if err != nil {
		return fmt.Errorf("Cannot initialize GPG: %s", err)
	}
	gpgUtil = util

	return nil
}

func appAction(c *cli.Context) error {
	if err := initGlobalServices(c); err != nil {
		return err
	}

	runServers(c)

	return nil
}

func initGlobalServices(c *cli.Context) error {
	if err := initGpgUtil(c); err != nil {
		return err
	}

	store = storage.NewMemoryStore()

	smtpMailFrom = c.String("mail-from")
	log.Printf("Sending mail from '%s'", smtpMailFrom)

	smtpOutHost := fmt.Sprintf("%v:%v", c.String("smtp-out-host"), c.Int("smtp-out-port"))
	log.Println("Using outgoing SMTP server at: ", smtpOutHost)
	mailSender = smtp.NewSingleServerSendMailer(smtpOutHost)

	return nil
}

func getHTTPHost(c *cli.Context) string {
	httpHost := fmt.Sprintf("%v:%v", c.String("host"), c.Int("http-port"))
	if c.Int("http-port") == 80 {
		httpHost = c.String("host")
	}
	return httpHost
}

func runServers(c *cli.Context) {
	httpHost := getHTTPHost(c)
	smtpInHost := fmt.Sprintf("%v:%v", c.String("host"), c.Int("smtp-in-port"))

	log.Println("Setting up SMTP server listening at: ", smtpInHost)
	go serveSMTPRequestReceiver(smtpInHost, httpHost)

	log.Println("Setting up HTTP server listening at: ", httpHost)
	log.Panic(serveNonceConfirmer(httpHost))
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

	err = initGpgUtil(c)
	if err != nil {
		return err
	}

	httpHost := getHTTPHost(c)
	processMail := getIncomingMailHandler(httpHost)
	processMail(inputMail)

	return nil
}

func confirmNonceAction(c *cli.Context) error {
	if err := initGpgUtil(c); err != nil {
		return err
	}

	nonceString := c.String("nonce")
	nonce, err := validator.NonceFromString(nonceString)
	if err != nil {
		return fmt.Errorf("Cannot parse nonce '%v': %v", nonceString, err)
	}

	handleNonceConfirmation(nonce)

	return nil
}

func cliErrorHandler(action func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) (e error) {
		defer func() {
			if r := recover(); r != nil {
				debug.PrintStack()
				e = cli.NewExitError(fmt.Sprintf("Panic: %v", r), errorExitCode)
			}
		}()

		if err := action(c); err != nil {
			return cli.NewExitError(fmt.Sprintf("Error: %v", err), errorExitCode)
		}

		return nil
	}
}

// subCommands to execute single aspects of the key validation process without requiring the full server startup.
var subCommands = []cli.Command{
	{
		Name:   "process-mail",
		Usage:  "process an incoming mail",
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
		Flags: append(
			[]cli.Flag{
				cli.StringFlag{
					Name:  "nonce",
					Value: "<missing>",
					Usage: "String value of the Nonce",
				},
			},
			privateKeyFlags...,
		),
	},
}

var privateKeyFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "private-key",
		Value: "./test/keys/test-gpg-validation@server.local (0x87144E5E) sec.asc.gpg",
		// TODO Handle missing value, use better default
		Usage: "`PRIVATE_KEY_PATH` to the private OpenPGP key of the server",
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
	app.Name = "OpenPGP Validation Service"
	app.Usage = "Run a server that manages email verification and signs verified keys with the servers OpenPGP key."
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
				Usage: "`PORT` for the HTTP nonce listener",
			},
			cli.IntFlag{
				Name:  "smtp-in-port",
				Value: 2525,
				Usage: "`SMTP_IN_PORT` on which the service will listen for incoming mails",
			},
			cli.IntFlag{
				Name:  "smtp-out-port",
				Value: 25,
				Usage: "`SMTP_OUT_PORT` of the SMTP server where outgoing mails will be sent to",
			},
			cli.StringFlag{
				Name:  "smtp-out-host",
				Value: "localhost",
				Usage: "`SMTP_HOST` of the SMTP server where outgoing mails will be sent to",
			},
			cli.StringFlag{
				Name:  "mail-from",
				Value: "openpgp-validation-server@server.local",
				Usage: "`MAIL_FROM` of outgoing mails. This is NOT the FROM header of the mail.",
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
