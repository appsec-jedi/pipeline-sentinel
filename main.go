package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ebpf/bpf.c -- -I./ebpf/headers -O2

type Event struct {
	PID     uint32
	PPID    uint32
	BinPath [256]byte
}

func readFullCommand(pid uint32, fallback string) string {
	procCmdline := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineBytes, err := os.ReadFile(procCmdline)
	if err != nil {
		return fallback
	}

	fullCommand := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

	baseCommand := strings.Fields(fullCommand)
	if len(baseCommand) > 0 && (strings.HasSuffix(baseCommand[0], "bash") || strings.HasSuffix(baseCommand[0], "sh")) {
		time.Sleep(5 * time.Millisecond)
		cmdlineBytes, err = os.ReadFile(procCmdline)
		if err == nil {
			return strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
		}
	}

	return fullCommand
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("Successfully loaded and attached eBPF program. Waiting for events...")

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting program...")
		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf reader: %s", err)
		}
	}()

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf buffer failed: %s", err)
			continue
		}

		if record.LostSamples > 0 {
			log.Printf("lost %d events", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event failed: %s", err)
			continue
		}

		fullCommand := readFullCommand(event.PID, string(bytes.TrimRight(event.BinPath[:], "\x00")))

		log.Printf(
			"[PID: %d PPID: %d] Command: %s",
			event.PID, event.PPID,
			fullCommand,
		)
	}
}
