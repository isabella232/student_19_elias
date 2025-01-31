// Conode is the main binary for running a Cothority server.
// A conode can participate in various distributed protocols using the
// *onet* library as a network and overlay library and the *kyber*
// library for all cryptographic primitives.
// Basically, you first need to setup a config file for the server by using:
//
//  ./conode setup
//
// Then you can launch the daemon with:
//
//  ./conode
//
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"

	// Services that will be compiled in.
	_ "github.com/dedis/student_19_elias/blscosi_bundle"
	_ "go.dedis.ch/cothority/v3/authprox"
	_ "go.dedis.ch/cothority/v3/byzcoin"
	_ "go.dedis.ch/cothority/v3/byzcoin/contracts"
	_ "go.dedis.ch/cothority/v3/calypso"
	_ "go.dedis.ch/cothority/v3/eventlog"
	_ "go.dedis.ch/cothority/v3/evoting/service"
	_ "go.dedis.ch/cothority/v3/personhood"
	_ "go.dedis.ch/cothority/v3/skipchain"
	status "go.dedis.ch/cothority/v3/status/service"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/blscosi/check"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v4/app"
	"go.dedis.ch/onet/v4/cfgpath"
	"go.dedis.ch/onet/v4/log"
	"go.dedis.ch/onet/v4/network"
	cli "gopkg.in/urfave/cli.v1"
)

const (
	// DefaultName is the name of the binary we produce and is used to create a directory
	// folder with this name
	DefaultName = "conode"
)

var gitTag = ""

func main() {
	cliApp := cli.NewApp()
	cliApp.Name = DefaultName
	cliApp.Usage = "run a cothority server"
	if gitTag == "" {
		cliApp.Version = "unknown"
	} else {
		cliApp.Version = gitTag
	}
	status.Version = cliApp.Version

	cliApp.Commands = []cli.Command{
		{
			Name:    "setup",
			Aliases: []string{"s"},
			Usage:   "Setup server configuration (interactive)",
			Action:  setup,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "non-interactive",
					Usage: "generate private.toml in non-interactive mode",
				},
				cli.IntFlag{
					Name:  "port",
					Usage: "which port to listen on",
					Value: 6879,
				},
				cli.StringFlag{
					Name:  "description",
					Usage: "the description to use",
					Value: "configured in non-interactive mode",
				},
			},
		},
		{
			Name:   "server",
			Usage:  "Start cothority server",
			Action: runServer,
		},
		{
			Name:      "check",
			Aliases:   []string{"c"},
			Usage:     "Check if the servers in the group definition are up and running",
			ArgsUsage: "Cothority group definition file",
			Action:    checkConfig,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "g",
					Usage: "Cothority group definition file",
				},
				cli.BoolFlag{
					Name:  "detail, l",
					Usage: "Do pairwise signing and show full addresses",
				},
			},
		},
	}
	cliApp.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
		cli.StringFlag{
			Name:  "config, c",
			Value: path.Join(cfgpath.GetConfigPath(DefaultName), app.DefaultServerConfig),
			Usage: "Configuration file of the server",
		},
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}

	// Do not allow conode to run when built in 32-bit mode.
	// The dedis/protobuf package is the origin of this limit.
	// Instead of getting the error later from protobuf and being
	// confused, just make it totally clear up-front.
	var i int
	iType := reflect.TypeOf(i)
	if iType.Size() < 8 {
		log.ErrFatal(errors.New("conode cannot run when built in 32-bit mode"))
	}

	err := cliApp.Run(os.Args)
	log.ErrFatal(err)
}

// raiseFdLimit is a callback that is only set in the context where it is needed:
//  * when conode.go is used alone by ../libtest.sh, not needed
//  * when conode is build on windows, not needed
//  * when conode is build on unix, fd_unix.go sets it
var raiseFdLimit func()

func runServer(ctx *cli.Context) error {
	// first check the options
	config := ctx.GlobalString("config")
	if raiseFdLimit != nil {
		raiseFdLimit()
	}
	app.RunServer(config)
	return nil
}

// checkConfig contacts all servers and verifies if it receives a valid
// signature from each.
func checkConfig(c *cli.Context) error {
	tomlFileName := c.String("g")
	if c.NArg() > 0 {
		tomlFileName = c.Args().First()
	}
	if tomlFileName == "" {
		log.Fatal("[-] Must give the roster file to check.")
	}
	return check.CothorityCheck(tomlFileName, c.Bool("detail"))
}

func setup(c *cli.Context) error {
	if c.String("config") != "" {
		log.Fatal("[-] Configuration file option cannot be used for the 'setup' command")
	}
	if c.String("debug") != "" {
		log.Fatal("[-] Debug option cannot be used for the 'setup' command")
	}

	if c.Bool("non-interactive") {
		port := c.Int("port")
		portStr := fmt.Sprintf("%v", port)

		serverBinding := network.NewAddress(network.TLS, net.JoinHostPort("", portStr))
		kp := key.NewKeyPair(cothority.Suite)

		pub, _ := encoding.PointToStringHex(cothority.Suite, kp.Public)
		priv, _ := encoding.ScalarToStringHex(cothority.Suite, kp.Private)

		conf := &app.CothorityConfig{
			Suite:       cothority.Suite.String(),
			Public:      pub,
			Private:     priv,
			Address:     serverBinding,
			Description: c.String("description"),
			Services:    app.GenerateServiceKeyPairs(),
		}

		out := path.Join(cfgpath.GetConfigPath(DefaultName), app.DefaultServerConfig)
		err := conf.Save(out)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Wrote config file to %v\n", out)
		}

		// We are not going to write out the public.toml file here.
		// We don't because in the current use case for --non-interactive, which
		// is for containers to auto-generate configs on startup, the
		// roster (i.e. public IP addresses + public keys) will be generated
		// based on how Kubernetes does service discovery. Writing the public.toml
		// file based on the data we have here, would result in writing an invalid
		// public Address.

		// If we had written it, it would look like this:
		//  server := app.NewServerToml(cothority.Suite, kp.Public, conf.Address, conf.Description)
		//  group := app.NewGroupToml(server)
		//  group.Save(path.Join(dir, "public.toml"))

		return err
	}

	app.InteractiveConfig(cothority.Suite, DefaultName)
	return nil
}
