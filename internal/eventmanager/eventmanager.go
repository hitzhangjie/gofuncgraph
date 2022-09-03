package eventmanager

import (
	"errors"
	"fmt"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/jschwinger233/ufuncgraph/elf"
	"github.com/jschwinger233/ufuncgraph/internal/bpf"
	"github.com/jschwinger233/ufuncgraph/internal/uprobe"
)

type EventManager struct {
	elf     *elf.ELF
	uprobes map[string]uprobe.Uprobe

	goroutine2events map[uint64][]bpf.UfuncgraphEvent
	goroutine2stack  map[uint64]uint64
	bootTime         time.Time
}

func New(uprobes []uprobe.Uprobe, elf *elf.ELF) (_ *EventManager, err error) {
	host, err := sysinfo.Host()
	if err != nil {
		return
	}
	bootTime := host.Info().BootTime
	uprobesMap := map[string]uprobe.Uprobe{}
	for _, up := range uprobes {
		uprobesMap[fmt.Sprintf("%s+%d", up.Funcname, up.RelOffset)] = up
	}
	return &EventManager{
		elf:              elf,
		goroutine2events: map[uint64][]bpf.UfuncgraphEvent{},
		goroutine2stack:  map[uint64]uint64{},
		bootTime:         bootTime,
		uprobes:          uprobesMap,
	}, nil
}

func (p *EventManager) GetUprobe(event bpf.UfuncgraphEvent) (_ uprobe.Uprobe, err error) {
	syms, offset, err := p.elf.ResolveAddress(event.Ip)
	if err != nil {
		return
	}
	for _, sym := range syms {
		uprobe, ok := p.uprobes[fmt.Sprintf("%s+%d", sym.Name, offset)]
		if ok {
			return uprobe, nil
		}
	}
	err = errors.New("uprobe not found")
	return
}
