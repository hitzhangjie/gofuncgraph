/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var usage = `bpf(2)-based ftrace(1)-like function graph tracer for Go! 

for now, only support following cases:
- OS: Linux (always little endian)
- arch: x86-64
- binary: go ELF executable built with non-stripped non-PIE mode
`

var usageLong = `gofuncgraph is a bpf(2)-based ftrace(1)-like function graph tracer for Go!

here're some tracing examples:

1 trace a specific function in etcd client "go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire"
  gofuncgraph --uprobe-wildcards 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' ./binary

2 trace all functions in etcd client
  gofuncgraph --uprobe-wildcards 'go.etcd.io/etcd/client/v3/*' ./binary 

3 trace a specific function and include runtime.chan* builtins
  gofuncgraph -u 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' -u 'runtime.chan*' ./binary 

4 trace a specific function with some arguemnts
  gofuncgraph -u 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire(pfx=+0(+8(%ax)):c512, n_pfx=+16(%ax):u64, m.s.id=16(0(%ax)):u64 )' ./binary
 `

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gofuncgraph [-u wildcards|-x|-d] <binary> [fetch]",
	Short: usage,
	Long:  usageLong,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			log.SetLevel(log.DebugLevel)
		}

		if len(args) < 1 {
			fmt.Println(usage)
			return errors.New("too few args")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		bin := args[0]
		fetch := args[1:]
		excludeVendor, _ := cmd.Flags().GetBool("exclude-vendor")
		uprobeWildcards, _ := cmd.Flags().GetStringSlice("uprobe-wildcards")

		tracer, err := NewTracer(bin, excludeVendor, uprobeWildcards, fetch)
		if err != nil {
			return err
		}

		if err := initLimit(); err != nil {
			return err
		}

		return tracer.Start()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gofuncgraph.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.Flags().BoolP("debug", "d", false, "enable debug logging")
	rootCmd.Flags().BoolP("exclude-vendor", "x", true, "exclude vendor")
	rootCmd.Flags().StringSliceP("uprobe-wildcards", "u", nil, "wildcards for code to add uprobes")

	rootCmd.MarkFlagRequired("uprobe-wildcards")
}

func initLimit() error {
	rlimit := syscall.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_MEMLOCK: %w", err)
	}
	rlimit = syscall.Rlimit{
		Cur: 1048576,
		Max: 1048576,
	}
	if err := syscall.Setrlimit(unix.RLIMIT_NOFILE, &rlimit); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_NOFILE: %w", err)
	}
	return nil
}
