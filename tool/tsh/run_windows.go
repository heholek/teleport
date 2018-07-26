// +build windows

/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/sirupsen/logrus"
)

// Run executes the tsh client. It's called by main, but easier to test.
func Run(args []string, underTest bool) {
	var cf CLIConf
	cf.IsUnderTest = underTest
	utils.InitLogger(utils.LoggingForCLI, logrus.WarnLevel)

	localUser, _ := client.Username()

	// Configure CLI argument parser.
	app := utils.InitCLIParser("tsh", "TSH: Teleport SSH client").Interspersed(false)
	app.Flag("login", "Remote host login").Short('l').Envar("TELEPORT_LOGIN").StringVar(&cf.NodeLogin)
	app.Flag("proxy", "SSH proxy address").Envar("TELEPORT_PROXY").StringVar(&cf.Proxy)
	app.Flag("nocache", "do not cache cluster discovery locally").Hidden().BoolVar(&cf.NoCache)
	app.Flag("user", fmt.Sprintf("SSH proxy user [%s]", localUser)).Envar("TELEPORT_USER").StringVar(&cf.Username)
	app.Flag("ttl", "Minutes to live for a SSH session").Int32Var(&cf.MinsToLive)
	app.Flag("identity", "Identity file").Short('i').StringVar(&cf.IdentityFileIn)
	app.Flag("compat", "OpenSSH compatibility flag").Hidden().StringVar(&cf.Compatibility)
	app.Flag("cert-format", "SSH certificate format").StringVar(&cf.CertificateFormat)
	app.Flag("insecure", "Do not verify server's certificate and host name. Use only in test environments").Default("false").BoolVar(&cf.InsecureSkipVerify)
	app.Flag("auth", "Specify the type of authentication connector to use.").StringVar(&cf.AuthConnector)
	app.Flag("namespace", "Namespace of the cluster").Default(defaults.Namespace).Hidden().StringVar(&cf.Namespace)
	app.Flag("skip-version-check", "Skip version checking between server and client.").Hidden().BoolVar(&cf.SkipVersionCheck)
	debugMode := app.Flag("debug", "Verbose logging to stdout").Short('d').Bool()
	app.HelpFlag.Short('h')

	// login logs in with remote proxy and obtains a "session certificate" which gets
	// stored in ~/.tsh directory
	login := app.Command("login", "Log in to a cluster and retrieve the session certificate")
	login.Flag("out", "Identity output").Short('o').StringVar(&cf.IdentityFileOut)
	login.Flag("format", fmt.Sprintf("Identity format [%s] or %s (for OpenSSH compatibility)",
		client.DefaultIdentityFormat,
		client.IdentityFormatOpenSSH)).Default(string(client.DefaultIdentityFormat)).StringVar((*string)(&cf.IdentityFormat))
	login.Arg("cluster", clusterHelp).StringVar(&cf.SiteName)
	login.Alias(loginUsageFooter)

	// logout deletes obtained session certificates in ~/.tsh
	logout := app.Command("logout", "Delete a cluster certificate")

	// show key
	show := app.Command("show", "Read an identity from file and print to stdout").Hidden()
	show.Arg("identity_file", "The file containing a public key or a certificate").Required().StringVar(&cf.IdentityFileIn)

	// The status command shows which proxy the user is logged into and metadata
	// about the certificate.
	status := app.Command("status", "Display the list of proxy servers and retrieved certificates")

	ver := app.Command("version", "Print the version")

	// parse CLI commands+flags:
	command, err := app.Parse(args)
	if err != nil {
		utils.FatalError(err)
	}

	// apply -d flag:
	if *debugMode {
		utils.InitLogger(utils.LoggingForCLI, logrus.DebugLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		exitSignals := make(chan os.Signal, 1)
		signal.Notify(exitSignals, syscall.SIGTERM, syscall.SIGINT)

		select {
		case sig := <-exitSignals:
			logrus.Debugf("signal: %v", sig)
			cancel()
		}
	}()
	cf.Context = ctx

	switch command {
	case login.FullCommand():
		onLogin(&cf)
	case logout.FullCommand():
		refuseArgs(logout.FullCommand(), args)
		onLogout(&cf)
	case show.FullCommand():
		onShow(&cf)
	case status.FullCommand():
		onStatus(&cf)
	case ver.FullCommand():
		utils.PrintVersion()
	}
}
