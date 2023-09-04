//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/jschwinger233/gofuncgraph/version"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

func init() {
	rlimit := syscall.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		log.Fatal(err)
	}
	rlimit = syscall.Rlimit{
		Cur: 1048576,
		Max: 1048576,
	}
	if err := syscall.Setrlimit(unix.RLIMIT_NOFILE, &rlimit); err != nil {
		log.Fatal(err)
	}
}

func main() {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Print(version.String())
	}

	app := &cli.App{
		Name: "gofuncgraph",
		// TODO@zc: kernel version
		Usage: "bpf(2)-based ftrace(1)-like function graph tracer for Go! \n(only non-stripped non-PIE-built Golang ELF on x86-64 little-endian Linux is supported for now)",
		UsageText: `example: trace a specific function in etcd client "go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire"
  gofuncgraph <binary> 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire'

example: trace all functions in etcd client
  gofuncgraph <binary> 'go.etcd.io/etcd/client/v3/*'

example: trace a specific function and include runtime.chan* builtins
  gofuncgraph <binary> 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' 'runtime.chan*'

example: trace a specific function with some arguemnts
  gofuncgraph <binary> 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire(pfx=+0(+8(%ax)):c512, n_pfx=+16(%ax):u64, m.s.id=16(0(%ax)):u64 )'
 `,
		Version: version.VERSION,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "debug",
				Value: false,
				Usage: "enable debug logging",
			},
			&cli.BoolFlag{
				Name:  "exclude-vendor",
				Value: true,
			},
			&cli.StringSliceFlag{
				Name:     "uprobe-wildcards",
				Required: true,
			},
		},
		Before: func(c *cli.Context) error {
			if c.Bool("debug") {
				log.SetLevel(log.DebugLevel)
			}
			return nil
		},
		Action: func(ctx *cli.Context) (err error) {
			bin := ctx.Args().First()
			args := ctx.Args().Tail()

			if bin == "" || ctx.Bool("help") {
				return cli.ShowAppHelp(ctx)
			}

			tracer, err := NewTracer(bin, ctx.Bool("exclude-vendor"), ctx.StringSlice("uprobe-wildcards"), args)
			if err != nil {
				return
			}
			return tracer.Start()
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}
}
