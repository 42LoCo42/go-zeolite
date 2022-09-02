package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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

var trustList []string

func trust(otherPK zeolite.SignPK) (bool, error) {
	b64 := zeolite.Base64Enc(otherPK[:])
	fmt.Fprintln(os.Stderr, "Other:", b64)

	for _, id := range trustList {
		if id == b64 {
			return true, nil
		}
	}

	return len(trustList) == 0, nil
}

// address: protocol://value
// e.g. tcp://localhost:37812
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

	// init identity
	var identity zeolite.Identity
	if *identVar != "" {
		// read identity from base64 in env variable
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
		// read identity from file
		all, err := os.ReadFile(*identFile)
		if err != nil {
			panic(err)
		}
		copy(identity.Public[:], all)
		copy(identity.Secret[:], all[len(identity.Public):])
	} else {
		// if no identity was loaded, create a new one
		var err error
		identity, err = zeolite.NewIdentity()
		if err != nil {
			panic(err)
		}
	}

	// identities always have the public part come first
	if mode == "gen" {
		os.Stdout.Write(identity.Public[:])
		os.Stdout.Write(identity.Secret[:])
		fmt.Fprintf(os.Stderr, "%s-%s",
			zeolite.Base64Enc(identity.Public[:]),
			zeolite.Base64Enc(identity.Secret[:]))
		os.Exit(0)
	}

	trustList = *trustIDs

	for _, path := range *trustFiles {
		file, err := os.Open(path)
		if err != nil {
			panic(err)
		}
		scn := bufio.NewScanner(file)
		for scn.Scan() {
			trustList = append(trustList, scn.Text())
		}
	}

	fmt.Println(trustList)

	if !*noCheck && len(trustList) == 0 {
		panic("No trust specified")
	}

	fmt.Fprintln(os.Stderr, "Self: ", zeolite.Base64Enc(identity.Public[:]))

	if len(args) < 2 {
		panic("Not enough arguments")
	}

	// get address (required for all remaining modes)
	proto, val, err := parseAddr(args[1])
	if err != nil {
		panic(err)
	}

	switch mode {
	case "client":
		conn, err := net.Dial(proto, val)
		if err != nil {
			panic(err)
		}

		simple(identity, conn)
	case "single":
		conn, err := net.Listen(proto, val)
		if err != nil {
			panic(err)
		}

		client, err := conn.Accept()
		if err != nil {
			panic(err)
		}

		simple(identity, client)
	case "multi":
		if len(args) < 3 {
			panic("Not enough arguments")
		}

		conn, err := net.Listen(proto, val)
		if err != nil {
			panic(err)
		}

		// main loop: accept new clients, spawn child processes and handlers
		for {
			// TODO: handle errors more gracefully

			// accept client
			client, err := conn.Accept()
			if err != nil {
				panic(err)
			}

			// open zeolite stream
			stream, err := identity.NewStream(client, trust)
			if err != nil {
				panic(err)
			}

			// create child process
			child := exec.Command(args[2], args[3:]...)

			// get pipes
			in, err := child.StdinPipe()
			if err != nil {
				panic(err)
			}
			out, err := child.StdoutPipe()
			if err != nil {
				panic(err)
			}
			oer, err := child.StderrPipe()
			if err != nil {
				panic(err)
			}

			// start child
			if err := child.Start(); err != nil {
				panic(err)
			}

			// start await, data transfer & stderr display
			go child.Wait()
			go bidi(stream, out, in)
			go io.Copy(os.Stderr, oer)
		}
	default:
		panic(fmt.Sprint("Unknown mode: ", mode))
	}
}

func simple(identity zeolite.Identity, conn net.Conn) {
	stream, err := identity.NewStream(conn, trust)
	if err != nil {
		panic(err)
	}

	bidi(stream, os.Stdin, os.Stdout)
}

func bidi(stream zeolite.Stream, src io.ReadCloser, dst io.WriteCloser) {
	// src -> stream
	go func() {
		io.Copy(stream, src)
		src.Close()
	}()

	// stream -> dst
	zeolite.BlockCopy(dst, stream)
	dst.Close()
}
