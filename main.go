package main

import (
	"fmt"
	"github.com/42LoCo42/go-zeolite/zeolite"
	"github.com/pborman/getopt/v2"
	"net"
	"os"
	"strings"
)

const (
	identVarHelp   = "Environment variable storing base64-encoded identity"
	identFileHelp  = "File storing identity"
	noCheckHelp    = "Disable trust checking"
	trustIDsHelp   = "Trust this base64-encoded ID"
	trustFilesHelp = "Trust all base64-encoded IDs in this file"
	showHelpHelp   = "Show this help"
)

const usage = `Usage: %s [options] <mode>
Options:
	-i <name>              %s
	-I <file>              %s
	-k                     %s
	-t <client ID>         %s
	-T <client ID file>    %s
	-h                     %s

Modes:
	gen: Generate new identity. It will be printed to stdout in raw form
		and to stderr in base64-encoded form.

	client <address>: Connects to the specified address.
		stdin is sent and received data is printed to stdout.

	single <address>: Starts a server that accepts a single connection.
		stdin is sent and received data is printed to stdout.

	multi <address> <cmd> [args]: Starts a multi handler server.
		It will spawn cmd with args for each connection,
		pass received data to stdin and send data read from stdout.

	Available address formats:
		tcp://host:port
		tcp4://host:port
		tcp4://host:port
		unix://path
`

func printUsage() {
	parts := strings.Split(os.Args[0], "/")
	fmt.Fprintf(
		os.Stderr, usage, parts[len(parts)-1],
		identVarHelp, identFileHelp, noCheckHelp,
		trustIDsHelp, trustFilesHelp, showHelpHelp,
	)
}

func trustAll(otherPK zeolite.SignPK) (bool, error) {
	fmt.Fprintln(os.Stderr, "Other:", zeolite.Base64PK(otherPK))
	return true, nil
}

func main() {
	identVar := getopt.String('i', "", identVarHelp, "var")
	identFile := getopt.String('I', "", identFileHelp, "file")
	noCheck := getopt.Bool('k', noCheckHelp)
	trustIDs := getopt.List('t', trustIDsHelp, "id")
	trustFiles := getopt.List('T', trustFilesHelp, "file")
	showHelp := getopt.Bool('h', showHelpHelp)

	getopt.SetUsage(printUsage)
	getopt.Parse()

	if *showHelp {
		getopt.Usage()
		os.Exit(0)
	}

	fmt.Println(*identVar)
	fmt.Println(*identFile)
	fmt.Println(*noCheck)
	fmt.Println(*trustIDs)
	fmt.Println(*trustFiles)
	os.Exit(1)

	if err := zeolite.Init(); err != nil {
		panic(err)
	}

	identity, err := zeolite.NewIdentity()
	if err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, "Self: ", zeolite.Base64PK(identity.Public))

	var conn net.Conn
	if os.Args[1] == "client" {
		conn, err = net.Dial("tcp", "localhost:37812")
		if err != nil {
			panic(err)
		}
	} else {
		ln, err := net.Listen("tcp", "0:37812")
		if err != nil {
			panic(err)
		}

		conn, err = ln.Accept()
		if err != nil {
			panic(err)
		}
	}

	stream, err := identity.NewStream(conn, trustAll)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(0)
			}
			fmt.Print(string(msg))
		}
	}()

	buf := make([]byte, 1<<20)
	for {
		if _, err := os.Stdin.Read(buf); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(0)
		}
		if err := stream.Send(buf); err != nil {
			panic(err)
		}
	}
}
