package main

import (
	"fmt"
	"github.com/TNG/gpg-validation-server/mail"
	"github.com/codegangsta/cli"
	"log"
	"os"
)

const errorExitCode = 1

func appAction(c *cli.Context) error {
	fmt.Println("Args", c.Args())
	fmt.Println("host", c.String("host"))
	// TODO #11 Start the servers
	return nil
}

func processMailAction(c *cli.Context) error {
	var err error
	var input *os.File

	file := c.String("file")

	if file == "" {
		input = os.Stdin
	} else {
		input, err = os.Open(file)
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
	}

	parser := mail.Parser{nil}
	entity, _ := parser.ParseMail(input)
	log.Println(entity)

	return nil
}

func cliErrorHandler(action func(*cli.Context) error) func(*cli.Context) cli.ExitCoder {
	return func(c *cli.Context) cli.ExitCoder {
		if err := action(c); err != nil {
			return cli.NewExitError(fmt.Sprint("Error: ", err), errorExitCode)
		}
		return nil
	}
}

func runApp(args []string) {
	app := cli.NewApp()
	app.Name = "GPG Validation Service"
	app.Usage = "Run a server that manages email verification and signs verified keys with the servers GPG key."

	app.Commands = []cli.Command{
		{
			Name:   "process-mail",
			Usage:  "process an incoming email",
			Action: cliErrorHandler(processMailAction),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "file",
					Value: "",
					Usage: "`FILE_PATH` of the mail file, omit to read from stdin ",
				},
			},
		},
	}

	app.Action = cliErrorHandler(appAction)
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "host",
			Value: "localhost",
			Usage: "`HOST` of the mail server",
		},
	}

	err := app.Run(args)
	if err != nil {
		cli.OsExiter(errorExitCode)
	}
}

func main() {
	runApp(os.Args)
}
