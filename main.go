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
	"github.com/fatih/color"

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
	white_list   []string `yaml:"white_list,omitempty"`
}

func readFullCommand(pid uint32, fallback string) string {
	procCommandLine := fmt.Sprintf("/proc/%d/cmdline", pid)
	var commandLineBytes []byte
	var err error

	for range 5 {
		commandLineBytes, err = os.ReadFile(procCommandLine)
		if err == nil {
			break
		}
		time.Sleep(3 * time.Millisecond)
	}

	if err != nil {
		return fallback
	}

	return strings.ReplaceAll(string(commandLineBytes), "\x00", " ")
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
		words := strings.Fields(fullCommand)

		// fmt.Printf("\nFull command: %s\n", fullCommand)

		for _, rule := range rules {
			if rule.MatchCommand != "" {
				for _, word := range words {
					if word == rule.MatchCommand || strings.HasSuffix(word, "/"+rule.MatchCommand) {
						switch rule.Severity {
						case "critical":
							color.Red("\n[CRITICAL ALERT] - Failing build\nRule '%s' triggered (Severity: %s)\n\tCommand: %s\n",
								rule.Id, rule.Severity, fullCommand)
							os.Exit(1)
						case "high":
							color.Yellow("\n[ALERT] Rule '%s' triggered (Severity: %s)\n\tCommand: %s\n",
								rule.Id, rule.Severity, fullCommand)
						default:
							color.Yellow("\n[ALERT] Rule '%s' triggered (Severity: %s)\n\tCommand: %s\n",
								rule.Id, rule.Severity, fullCommand)
						}
						break
					}
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
					if len(rule.white_list) > 0 {
						for _, allowed := range rule.white_list {
							if strings.Contains(fullCommand, allowed) {
								fmt.Println("\nWhitelisted command found:")
								fmt.Printf("\t%s", fullCommand)
								break
							}
						}
					}
					switch rule.Severity {
					case "critical":
						color.Red("\n[CRITICAL ALERT] - Failing build\nRule '%s' triggered (Severity: %s)\n\tCommand: %s\n",
							rule.Id, rule.Severity, fullCommand)
						os.Exit(1)
					case "high":
						color.Yellow("\n[ALERT] Rule '%s' triggered (Severity: %s)\n\tCommand: %s\n",
							rule.Id, rule.Severity, fullCommand)
					default:
						color.Yellow("\n[ALERT] Rule '%s' triggered (Severity: %s)\n\tCommand: %s\n",
							rule.Id, rule.Severity, fullCommand)
					}
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
