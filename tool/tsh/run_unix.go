// +build !windows

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

	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
)

// Run executes the tsh client. It's called by main, but easier to test.
func Run(args []string, underTest bool) {
	var cf CLIConf
	cf.IsUnderTest = underTest
	utils.InitLogger(utils.LoggingForCLI, logrus.WarnLevel)

	// configure CLI argument parser:
	app := utils.InitCLIParser("tsh", "TSH: Teleport SSH client").Interspersed(false)
	app.Flag("login", "Remote host login").Short('l').Envar("TELEPORT_LOGIN").StringVar(&cf.NodeLogin)
	localUser, _ := client.Username()
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
	app.Flag("gops", "Start gops endpoint on a given address").Hidden().BoolVar(&cf.Gops)
	app.Flag("gops-addr", "Specify gops addr to listen on").Hidden().StringVar(&cf.GopsAddr)
	app.Flag("skip-version-check", "Skip version checking between server and client.").Hidden().BoolVar(&cf.SkipVersionCheck)
	debugMode := app.Flag("debug", "Verbose logging to stdout").Short('d').Bool()
	app.HelpFlag.Short('h')
	ver := app.Command("version", "Print the version")
	// ssh
	ssh := app.Command("ssh", "Run shell or execute a command on a remote SSH node")
	ssh.Arg("[user@]host", "Remote hostname and the login to use").Required().StringVar(&cf.UserHost)
	ssh.Arg("command", "Command to execute on a remote host").StringsVar(&cf.RemoteCommand)
	ssh.Flag("port", "SSH port on a remote host").Short('p').Int32Var(&cf.NodePort)
	ssh.Flag("forward-agent", "Forward agent to target node").Short('A').BoolVar(&cf.ForwardAgent)
	ssh.Flag("forward", "Forward localhost connections to remote server").Short('L').StringsVar(&cf.LocalForwardPorts)
	ssh.Flag("local", "Execute command on localhost after connecting to SSH node").Default("false").BoolVar(&cf.LocalExec)
	ssh.Flag("tty", "Allocate TTY").Short('t').BoolVar(&cf.Interactive)
	ssh.Flag("cluster", clusterHelp).Envar(clusterEnvVar).StringVar(&cf.SiteName)

	// join
	join := app.Command("join", "Join the active SSH session")
	join.Flag("cluster", clusterHelp).Envar(clusterEnvVar).StringVar(&cf.SiteName)
	join.Arg("session-id", "ID of the session to join").Required().StringVar(&cf.SessionID)
	// play
	play := app.Command("play", "Replay the recorded SSH session")
	play.Flag("cluster", clusterHelp).Envar(clusterEnvVar).StringVar(&cf.SiteName)
	play.Arg("session-id", "ID of the session to play").Required().StringVar(&cf.SessionID)
	// scp
	scp := app.Command("scp", "Secure file copy")
	scp.Flag("cluster", clusterHelp).Envar(clusterEnvVar).StringVar(&cf.SiteName)
	scp.Arg("from, to", "Source and destination to copy").Required().StringsVar(&cf.CopySpec)
	scp.Flag("recursive", "Recursive copy of subdirectories").Short('r').BoolVar(&cf.RecursiveCopy)
	scp.Flag("port", "Port to connect to on the remote host").Short('P').Int32Var(&cf.NodePort)
	scp.Flag("quiet", "Quiet mode").Short('q').BoolVar(&cf.Quiet)
	// ls
	ls := app.Command("ls", "List remote SSH nodes")
	ls.Flag("cluster", clusterHelp).Envar(clusterEnvVar).StringVar(&cf.SiteName)
	ls.Arg("labels", "List of labels to filter node list").StringVar(&cf.UserHost)
	// clusters
	clusters := app.Command("clusters", "List available Teleport clusters")
	clusters.Flag("quiet", "Quiet mode").Short('q').BoolVar(&cf.Quiet)

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

	// bench
	bench := app.Command("bench", "Run shell or execute a command on a remote SSH node").Hidden()
	bench.Flag("cluster", clusterHelp).Envar(clusterEnvVar).StringVar(&cf.SiteName)
	bench.Arg("[user@]host", "Remote hostname and the login to use").Required().StringVar(&cf.UserHost)
	bench.Arg("command", "Command to execute on a remote host").Required().StringsVar(&cf.RemoteCommand)
	bench.Flag("port", "SSH port on a remote host").Short('p').Int32Var(&cf.NodePort)
	bench.Flag("threads", "Concurrent threads to run").Default("10").IntVar(&cf.BenchThreads)
	bench.Flag("duration", "Test duration").Default("1s").DurationVar(&cf.BenchDuration)
	bench.Flag("rate", "Requests per second rate").Default("10").IntVar(&cf.BenchRate)
	bench.Flag("interactive", "Create interactive SSH session").BoolVar(&cf.BenchInteractive)

	// show key
	show := app.Command("show", "Read an identity from file and print to stdout").Hidden()
	show.Arg("identity_file", "The file containing a public key or a certificate").Required().StringVar(&cf.IdentityFileIn)

	// The status command shows which proxy the user is logged into and metadata
	// about the certificate.
	status := app.Command("status", "Display the list of proxy servers and retrieved certificates")

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

	if cf.Gops {
		logrus.Debugf("starting gops agent")
		err = gops.Listen(&gops.Options{Addr: cf.GopsAddr})
		if err != nil {
			logrus.Warningf("failed to start gops agent %v", err)
		}
	}

	switch command {
	case ver.FullCommand():
		utils.PrintVersion()
	case ssh.FullCommand():
		onSSH(&cf)
	case bench.FullCommand():
		onBenchmark(&cf)
	case join.FullCommand():
		onJoin(&cf)
	case scp.FullCommand():
		onSCP(&cf)
	case play.FullCommand():
		onPlay(&cf)
	case ls.FullCommand():
		onListNodes(&cf)
	case clusters.FullCommand():
		onListSites(&cf)
	case login.FullCommand():
		onLogin(&cf)
	case logout.FullCommand():
		refuseArgs(logout.FullCommand(), args)
		onLogout(&cf)
	case show.FullCommand():
		onShow(&cf)
	case status.FullCommand():
		onStatus(&cf)
	}
}
