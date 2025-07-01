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
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"gopkg.in/yaml.v3"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ebpf/bpf.c -- -I./ebpf/headers -O2

type Event struct {
	PID     uint32
	PPID    uint32
	BinPath [256]byte
}

type Rule struct {
	Id           string   `yaml:"id"`
	Description  string   `yaml:"description"`
	Severity     string   `yaml:"severity"`
	MatchCommand string   `yaml:"match_command,omitempty"`
	MatchAll     []string `yaml:"match_all,omitempty"`
}

func readFullCommand(pid uint32, fallback string) string {
	procCommandline := fmt.Sprintf("/proc/%d/cmdline", pid)
	commandlineBytes, err := os.ReadFile(procCommandline)
	if err != nil {
		return fallback
	}

	fullCommand := strings.ReplaceAll(string(commandlineBytes), "\x00", " ")

	baseCommand := strings.Fields(fullCommand)
	if len(baseCommand) > 0 && (strings.HasSuffix(baseCommand[0], "bash") || strings.HasSuffix(baseCommand[0], "sh")) {
		time.Sleep(5 * time.Millisecond)
		commandlineBytes, err = os.ReadFile(procCommandline)
		if err == nil {
			return strings.ReplaceAll(string(commandlineBytes), "\x00", " ")
		}
	}

	return fullCommand
}

func loadRules() []Rule {
	fmt.Println("Loading rules file")
	yamlFile, err := os.ReadFile("/app/rules.yaml")
	if err != nil {
		log.Fatalf("Error loading rules file: %s", err)
	}

	var rules []Rule
	err = yaml.Unmarshal(yamlFile, &rules)
	if err != nil {
		log.Fatalf("Error with yaml unmarshal: %s", err)
	}

	fmt.Printf("Successfully loaded %d rules\n", len(rules))

	return rules
}

func processEvents(waitGroup *sync.WaitGroup, eventsChannel <-chan Event, rules []Rule) {
	defer waitGroup.Done()

	for event := range eventsChannel {
		fullCommand := readFullCommand(event.PID, string(bytes.TrimRight(event.BinPath[:], "\x00")))

		for _, rule := range rules {
			if rule.MatchCommand != "" {
				if strings.Contains(fullCommand, rule.MatchCommand) {
					log.Printf("[ALERT] Rule '%s' triggered (Severity: %s)\n\tDescription: %s\n\tCommand: %s\n",
						rule.Id, rule.Severity, rule.Description, fullCommand)
					break
				}
			}

			if len(rule.MatchAll) > 0 {
				allFound := true
				for _, pattern := range rule.MatchAll {
					if !strings.Contains(fullCommand, pattern) {
						allFound = false
						break
					}
				}
				if allFound {
					log.Printf("[ALERT] Rule '%s' triggered (Severity: %s)\n\tDescription: %s\n\tCommand: %s\n",
						rule.Id, rule.Severity, rule.Description, fullCommand)
					break
				}
			}
		}
	}
}

func main() {
	rules := loadRules()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	objects := bpfObjects{}
	if err := loadBpfObjects(&objects, nil); err != nil {
		log.Fatalf("Error loading objects: %v", err)
	}
	defer objects.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objects.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		log.Fatalf("Error attaching tracepoint: %s", err)
	}
	defer tp.Close()

	reader, err := perf.NewReader(objects.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Error creating perf event reader: %s", err)
	}

	var waitGroup sync.WaitGroup
	eventsChannel := make(chan Event, 100)

	waitGroup.Add(1)
	go processEvents(&waitGroup, eventsChannel, rules)

	log.Println("Successfully loaded and attached eBPF program. Waiting for events...")

	go func() {
		<-stopper
		log.Println("Received exit signal, exiting program...")

		if err := reader.Close(); err != nil {
			log.Fatalf("Error closing perf reader: %s", err)
		}
	}()

	var event Event
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			log.Printf("Error reading from perf buffer: %s", err)
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

		eventsChannel <- event
	}

	log.Println("Closing event channel...")
	close(eventsChannel)

	log.Println("Waiting for processor to finish...")
	waitGroup.Wait()

	log.Println("Shutdown complete.")
}
