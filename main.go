package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/42LoCo42/go-zeolite/zeolite"
	"github.com/pborman/getopt/v2"
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
	fmt.Fprintln(os.Stderr, "Other:", zeolite.Base64Enc(otherPK[:]))
	return true, nil
}

func parseAddr(addr string) (proto string, val string, err error) {
	parts := strings.Split(addr, "://")
	if len(parts) != 2 {
		return proto, val, errors.New("Invalid address form")
	} else {
		return parts[0], parts[1], nil
	}
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
	args := getopt.Args()

	if *showHelp {
		getopt.Usage()
		os.Exit(0)
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "missing mode")
		getopt.Usage()
		os.Exit(1)
	}
	mode := args[0]

	if err := zeolite.Init(); err != nil {
		panic(err)
	}

	var identity zeolite.Identity
	if *identVar != "" {
		val := os.Getenv(*identVar)
		parts := strings.Split(val, "-")
		if len(parts) != 2 {
			panic("Invalid data in variable")
		}
		r1 := base64.NewDecoder(base64.StdEncoding, strings.NewReader(parts[0]))
		r2 := base64.NewDecoder(base64.StdEncoding, strings.NewReader(parts[1]))
		public, err := io.ReadAll(r1)
		if err != nil {
			panic("Failed decoding public key")
		}
		secret, err := io.ReadAll(r2)
		if err != nil {
			panic("Failed decoding secret key")
		}
		copy(identity.Public[:], public)
		copy(identity.Secret[:], secret)
	} else if *identFile != "" {
		all, err := os.ReadFile(*identFile)
		if err != nil {
			panic(err)
		}
		copy(identity.Public[:], all)
		copy(identity.Secret[:], all[len(identity.Public):])
	} else {
		var err error
		identity, err = zeolite.NewIdentity()
		if err != nil {
			panic(err)
		}
	}

	if mode == "gen" {
		os.Stdout.Write(identity.Public[:])
		os.Stdout.Write(identity.Secret[:])
		fmt.Fprintf(os.Stderr, "%s-%s",
			zeolite.Base64Enc(identity.Public[:]), zeolite.Base64Enc(identity.Secret[:]))
		os.Exit(0)
	}

	fmt.Fprintln(os.Stderr, *noCheck)
	fmt.Fprintln(os.Stderr, *trustIDs)
	fmt.Fprintln(os.Stderr, *trustFiles)

	fmt.Fprintln(os.Stderr, "Self: ", zeolite.Base64Enc(identity.Public[:]))

	switch mode {
	case "client":
		if len(args) < 2 {
			panic("Not enough arguments")
		}
		proto, val, err := parseAddr(args[1])
		if err != nil {
			panic(err)
		}
		conn, err := net.Dial(proto, val)
		if err != nil {
			panic(err)
		}
		simple(identity, conn)
	case "single":
		if len(args) < 2 {
			panic("Not enough arguments")
		}
		proto, val, err := parseAddr(args[1])
		if err != nil {
			panic(err)
		}
		conn, err := net.Listen(proto, val)
		if err != nil {
			panic(err)
		}
		client, err := conn.Accept()
		if err != nil {
			panic(err)
		}
		simple(identity, client)
	default:
		panic(fmt.Sprint("Unknown mode: ", mode))
	}
}

func simple(identity zeolite.Identity, conn net.Conn) {
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
