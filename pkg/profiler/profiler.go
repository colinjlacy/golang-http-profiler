//go:build linux

package profiler

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	dirSend = 0
	dirRecv = 1
)

// Event mirrors the struct emitted from the BPF program. Keep layout/alignment identical.
type Event struct {
	Ts        uint64
	Pid       uint32
	Tid       uint32
	DataLen   uint32
	Sport     uint16
	Dport     uint16
	Family    uint16
	Direction uint8
	_         [1]byte // padding to align to 8 bytes for the following arrays
	Comm      [16]byte
	Saddr     [16]byte
	Daddr     [16]byte
	Data      [256]byte
}

type Parsed struct {
	Method     string
	URL        string
	Body       string
	StatusCode string
}

type Runner struct {
	targetPort uint16
	outputPath string
}

func NewRunner(port uint16, outputPath string) *Runner {
	return &Runner{targetPort: port, outputPath: outputPath}
}

func (r *Runner) Run(ctx context.Context) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	var objs profilerObjects
	if err := loadProfilerObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading bpf objects: %w", err)
	}
	defer objs.Close()

	links := []link.Link{}
	add := func(l link.Link, err error) error {
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	if err := add(link.Kprobe("__x64_sys_bind", objs.SysBind, nil)); err != nil {
		return fmt.Errorf("attach bind: %w", err)
	}
	if err := add(link.Kprobe("__x64_sys_connect", objs.SysConnect, nil)); err != nil {
		return fmt.Errorf("attach connect: %w", err)
	}
	if err := add(link.Kprobe("__x64_sys_accept4", objs.SysAccept4Enter, nil)); err != nil {
		return fmt.Errorf("attach accept4 enter: %w", err)
	}
	if err := add(link.Kretprobe("__x64_sys_accept4", objs.SysAccept4Exit, nil)); err != nil {
		return fmt.Errorf("attach accept4 exit: %w", err)
	}
	if err := add(link.Kprobe("__x64_sys_sendto", objs.SysSendto, nil)); err != nil {
		return fmt.Errorf("attach sendto: %w", err)
	}
	if err := add(link.Kprobe("__x64_sys_recvfrom", objs.SysRecvfromEnter, nil)); err != nil {
		return fmt.Errorf("attach recvfrom enter: %w", err)
	}
	if err := add(link.Kretprobe("__x64_sys_recvfrom", objs.SysRecvfromExit, nil)); err != nil {
		return fmt.Errorf("attach recvfrom exit: %w", err)
	}

	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf: %w", err)
	}
	defer rd.Close()

	outFile, err := os.OpenFile(r.outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	log.Printf("profiler attached, filtering for port %d, writing to %s", r.targetPort, r.outputPath)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		ev := (*Event)(unsafe.Pointer(&record.RawSample[0]))
		if !r.portMatches(ev) {
			continue
		}

		parsed := parseHTTP(ev)
		line := r.formatEvent(ev, parsed)
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("write log: %w", err)
		}
		writer.Flush()

		select {
		case <-ctx.Done():
			return nil
		case <-signals:
			return nil
		default:
		}
	}
}

func ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func (r *Runner) portMatches(ev *Event) bool {
	return ntohs(ev.Sport) == r.targetPort || ntohs(ev.Dport) == r.targetPort
}

func (r *Runner) formatEvent(ev *Event, parsed Parsed) string {
	dir := "send"
	if ev.Direction == dirRecv {
		dir = "recv"
	}
	sport := ntohs(ev.Sport)
	dport := ntohs(ev.Dport)
	saddr := ipFromBytes(ev.Family, ev.Saddr[:])
	daddr := ipFromBytes(ev.Family, ev.Daddr[:])
	payload := strings.TrimSpace(string(ev.Data[:ev.DataLen]))

	var parts []string
	parts = append(parts, fmt.Sprintf("ts=%s", time.Unix(0, int64(ev.Ts)).Format(time.RFC3339Nano)))
	parts = append(parts, fmt.Sprintf("pid=%d", ev.Pid))
	parts = append(parts, fmt.Sprintf("comm=%s", strings.Trim(string(ev.Comm[:]), "\x00")))
	parts = append(parts, fmt.Sprintf("dir=%s", dir))
	parts = append(parts, fmt.Sprintf("src=%s:%d", saddr, sport))
	parts = append(parts, fmt.Sprintf("dst=%s:%d", daddr, dport))
	parts = append(parts, fmt.Sprintf("bytes=%d", ev.DataLen))

	if parsed.Method != "" {
		parts = append(parts, fmt.Sprintf("method=%s", parsed.Method))
	}
	if parsed.URL != "" {
		parts = append(parts, fmt.Sprintf("url=%s", parsed.URL))
	}
	if parsed.StatusCode != "" {
		parts = append(parts, fmt.Sprintf("status=%s", parsed.StatusCode))
	}
	if parsed.Body != "" {
		parts = append(parts, fmt.Sprintf("body=%s", parsed.Body))
	}

	parts = append(parts, fmt.Sprintf("raw=%q", payload))
	return strings.Join(parts, " ")
}

func parseHTTP(ev *Event) Parsed {
	var out Parsed
	data := ev.Data[:ev.DataLen]
	text := string(data)

	if ev.Direction == dirSend {
		fields := strings.Fields(text)
		if len(fields) >= 2 && isHTTPMethod(fields[0]) {
			out.Method = fields[0]
			out.URL = fields[1]
			out.Body = extractBody(text)
		}
	} else {
		if strings.HasPrefix(text, "HTTP/1.") || strings.HasPrefix(text, "HTTP/2") {
			parts := strings.SplitN(text, " ", 3)
			if len(parts) >= 2 {
				out.StatusCode = strings.TrimSpace(parts[1])
			}
			out.Body = extractBody(text)
		}
	}
	return out
}

func extractBody(payload string) string {
	parts := strings.SplitN(payload, "\r\n\r\n", 2)
	if len(parts) < 2 {
		return ""
	}
	body := strings.TrimSpace(parts[1])
	if len(body) > 120 {
		body = body[:120] + "..."
	}
	return body
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}

func ipFromBytes(family uint16, raw []byte) netip.Addr {
	switch family {
	case syscall.AF_INET:
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]})
	case syscall.AF_INET6:
		var b [16]byte
		copy(b[:], raw)
		return netip.AddrFrom16(b)
	default:
		return netip.Addr{}
	}
}
