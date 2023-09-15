package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"

	"github.com/jschwinger233/gofuncgraph/elf"
	"github.com/jschwinger233/gofuncgraph/internal/bpf"
	"github.com/jschwinger233/gofuncgraph/internal/eventmanager"
	"github.com/jschwinger233/gofuncgraph/internal/uprobe"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	OffsetPattern *regexp.Regexp
)

func init() {
	OffsetPattern = regexp.MustCompile(`\+\d+$`)
}

type Tracer struct {
	bin             string
	elf             *elf.ELF
	excludeVendor   bool
	uprobeWildcards []string
	args            []string

	bpf *bpf.BPF
}

func NewTracer(bin string, excludeVendor bool, uprobeWildcards, args []string) (_ *Tracer, err error) {
	elf, err := elf.New(bin)
	if err != nil {
		return
	}

	return &Tracer{
		bin:             bin,
		elf:             elf,
		excludeVendor:   excludeVendor,
		uprobeWildcards: uprobeWildcards,
		args:            args,

		bpf: bpf.New(),
	}, nil
}

func (t *Tracer) ParseArgs(inputs []string) (in []string, fetch map[string]map[string]string, err error) {
	fetch = map[string]map[string]string{}
	for _, input := range inputs {
		if input[len(input)-1] == ')' {
			stack := []byte{')'}
			for i := len(input) - 2; i >= 0; i-- {
				if input[i] == ')' {
					stack = append(stack, ')')
				} else if input[i] == '(' {
					if len(stack) > 0 && stack[len(stack)-1] == ')' {
						stack = stack[:len(stack)-1]
					} else {
						err = fmt.Errorf("imbalanced parenthese: %s", input)
						return
					}
				}

				if len(stack) == 0 {
					funcname := input[:i]
					fetch[funcname] = map[string]string{}
					for _, part := range strings.Split(input[i+1:len(input)-1], ",") {
						varState := strings.Split(part, "=")
						if len(varState) != 2 {
							err = fmt.Errorf("invalid variable statement: %s", varState)
							return
						}
						fetch[funcname][strings.TrimSpace(varState[0])] = strings.TrimSpace(varState[1])
					}
					input = input[:i]
					break
				}
			}
			if len(stack) > 0 {
				err = fmt.Errorf("imbalanced parenthese: %s", input)
				return
			}
		}

		in = append(in, input)
	}
	return
}

func (t *Tracer) Start() (err error) {
	in, fetch, err := t.ParseArgs(t.args)
	if err != nil {
		return
	}
	uprobes, err := uprobe.Parse(t.elf, &uprobe.ParseOptions{
		ExcludeVendor:   t.excludeVendor,
		UprobeWildcards: t.uprobeWildcards,
		OutputWildcards: in,
		Fetch:           fetch,
	})
	if err != nil {
		return
	}

requireConfirm:
	fmt.Fprintf(os.Stdout, "found %d uprobes, large number of uprobes (>1000) need long time for attaching and detaching, continue? [Y/n]\n", len(uprobes))
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return errors.WithStack(err)
	}
	switch strings.TrimSpace(input) {
	case "n", "N":
		return
	case "y", "Y":
		break
	default:
		goto requireConfirm
	}

	goidOffset, err := t.elf.FindGoidOffset()
	if err != nil {
		return
	}
	gOffset, err := t.elf.FindGOffset()
	if err != nil {
		return
	}
	log.Debugf("offset of goid from g is %d, offset of g from fs is -0x%x\n", goidOffset, -gOffset)
	if err = t.bpf.Load(uprobes, bpf.LoadOptions{
		GoidOffset: goidOffset,
		GOffset:    gOffset,
	}); err != nil {
		return
	}
	if err = t.bpf.Attach(t.bin, uprobes); err != nil {
		return
	}

	defer t.bpf.Detach()
	log.Info("start tracing\n")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	eventManager, err := eventmanager.New(uprobes, t.elf, t.bpf.PollArg(ctx))
	if err != nil {
		return
	}

	for event := range t.bpf.PollEvents(ctx) {
		if err = eventManager.Handle(event); err != nil {
			return
		}
	}
	return eventManager.PrintRemaining()
}
