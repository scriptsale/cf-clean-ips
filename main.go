package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cfRangesURL = "https://www.cloudflare.com/ips-v4"
const cacheTTL = 5 * time.Minute
const maxWorkers = 64

type scanParams struct {
	perCIDR   int
	timeoutMs int
	port      string
	sni       string
}

func (p scanParams) key() string {
	return fmt.Sprintf("%d|%d|%s|%s", p.perCIDR, p.timeoutMs, p.port, p.sni)
}

type cacheEntry struct {
	ips []string
	at  time.Time
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*cacheEntry{}
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", handle)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Println("listening on :" + port)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	p := scanParams{
		perCIDR:   atoiClamp(q.Get("per"), 5, 1, 30),
		timeoutMs: atoiClamp(q.Get("timeout"), 2500, 500, 8000),
		port:      firstNonEmpty(q.Get("port"), "443"),
		sni:       firstNonEmpty(q.Get("sni"), "www.cloudflare.com"),
	}
	fresh := q.Get("fresh") == "1"

	cacheMu.Lock()
	defer cacheMu.Unlock()

	if !fresh {
		if e, ok := cache[p.key()]; ok && time.Since(e.at) < cacheTTL {
			respond(w, e.ips, q.Get("format"), e.at)
			return
		}
	}

	startedAt := time.Now()
	ips, err := scan(p)
	if err != nil {
		http.Error(w, "scan failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	cache[p.key()] = &cacheEntry{ips: ips, at: time.Now()}
	respond(w, ips, q.Get("format"), startedAt)
}

func respond(w http.ResponseWriter, ips []string, format string, checkedAt time.Time) {
	w.Header().Set("X-Checked-At", checkedAt.UTC().Format(time.RFC3339))
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"count":      len(ips),
			"checked_at": checkedAt.UTC().Format(time.RFC3339),
			"ips":        ips,
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, strings.Join(ips, "\n")+"\n")
}

func scan(p scanParams) ([]string, error) {
	cidrs, err := fetchCIDRs()
	if err != nil {
		return nil, err
	}

	var candidates []string
	for _, c := range cidrs {
		candidates = append(candidates, randomIPsFromCIDR(c, p.perCIDR)...)
	}
	candidates = unique(candidates)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no candidate IPs generated from %d CIDRs", len(cidrs))
	}

	timeout := time.Duration(p.timeoutMs) * time.Millisecond
	jobs := make(chan string, len(candidates))
	for _, ip := range candidates {
		jobs <- ip
	}
	close(jobs)

	workers := maxWorkers
	if len(candidates) < workers {
		workers = len(candidates)
	}

	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok []string
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if testIP(ip, p.port, p.sni, timeout) {
					mu.Lock()
					ok = append(ok, ip)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	sortIPs(ok)
	return ok, nil
}

func testIP(ip, port, sni string, timeout time.Duration) bool {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, port), &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf(
		"GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n",
		sni,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	head := string(buf[:n])
	for _, ok := range []string{"HTTP/1.1 2", "HTTP/1.1 3", "HTTP/1.0 2", "HTTP/1.0 3"} {
		if strings.HasPrefix(head, ok) {
			return true
		}
	}
	return false
}

func fetchCIDRs() ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(cfRangesURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare ranges: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if _, _, err := net.ParseCIDR(line); err == nil && strings.Contains(line, ".") {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty cloudflare range list")
	}
	return out, nil
}

func randomIPsFromCIDR(cidr string, count int) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil
	}
	hostBits := bits - ones
	size := uint64(1) << uint(hostBits)

	base := binary.BigEndian.Uint32(ip4)
	if size <= 2 {
		return []string{ip4.String()}
	}
	maxOff := int64(size - 2)
	if int64(count) > maxOff {
		count = int(maxOff)
	}
	var out []string
	for i := 0; i < count; i++ {
		v := base + uint32(rand.Int63n(maxOff)+1)
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v)))
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		return ipToUint(ips[i]) < ipToUint(ips[j])
	})
}

func ipToUint(s string) uint32 {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0
	}
	b := ip.To4()
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func atoiClamp(s string, def, min, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
