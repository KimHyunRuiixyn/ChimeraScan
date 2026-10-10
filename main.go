package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ==================================================================
// Colors
// ==================================================================
const (
	cReset  = "\033[0m"
	cRed    = "\033[91m"
	cGreen  = "\033[92m"
	cYellow = "\033[93m"
	cBlue   = "\033[94m"
	cMag    = "\033[95m"
	cCyan   = "\033[96m"
	cDim    = "\033[2m"
	cBold   = "\033[1m"
)

// ==================================================================
// Paths
// ==================================================================
const (
	fuzzPlaceholder = "FUZZ"

	lfiFuzzFile    = "lfi/fuzzing/payload.txt"
	lfiNofuzzFile  = "lfi/nofuzz/payload.txt"
	crlfFile       = "crlf/payload.txt"
	ssrfFuzzFile   = "ssrf/fuzzing/payload.txt"
	ssrfNofuzzFile = "ssrf/nofuzz/payload.txt"
	orFuzzFile     = "openredirect/fuzzing/payload.txt"
	orNofuzzFile   = "openredirect/nofuzz/payload.txt"
	xssFuzzFile    = "xss/fuzzing/payload.txt"

	defaultUAFile  = "Ua.txt"
	defaultPocFile = "poc.txt"

	defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// ==================================================================
// Globals
// ==================================================================
var (
	httpClient    *http.Client
	verbose       bool
	hitLimit      int   // 0 = unlimited (scan all payloads)
	printMu       sync.Mutex
	reqCount      int64
	hitCount      int64
	stopRequested int32
	interrupted   bool

	userAgents  []string
	uaMu        sync.Mutex
	uaIndex     int
	uaRandomize bool
)

// ==================================================================
// Ctrl+C handler
// ==================================================================
func init() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if atomic.CompareAndSwapInt32(&stopRequested, 0, 1) {
			interrupted = true
			printMu.Lock()
			fmt.Printf("\n\n%s[!] Ctrl+C received — stopping gracefully...%s\n", cYellow, cReset)
			fmt.Printf("%s    Finishing active requests & saving PoC...%s\n", cDim, cReset)
			fmt.Printf("%s    Press Ctrl+C again to force exit.%s\n", cDim, cReset)
			printMu.Unlock()
		} else {
			printMu.Lock()
			fmt.Printf("\n%s[!] Force exit.%s\n", cRed, cReset)
			printMu.Unlock()
			os.Exit(130)
		}
	}()
}

func shouldStop() bool {
	return atomic.LoadInt32(&stopRequested) == 1
}

// reachedHitLimit: return true kalau hitLimit > 0 DAN hitCount >= hitLimit
func reachedHitLimit() bool {
	if hitLimit <= 0 {
		return false
	}
	return atomic.LoadInt64(&hitCount) >= int64(hitLimit)
}

// ==================================================================
// User-Agent rotation
// ==================================================================
func loadUserAgents(path string) {
	userAgents = nil
	if path != "" {
		if f, err := os.Open(path); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				userAgents = append(userAgents, line)
			}
		}
	}
	if len(userAgents) == 0 {
		userAgents = []string{defaultUA}
	}
}

func nextUA() string {
	if len(userAgents) == 0 {
		return defaultUA
	}
	if len(userAgents) == 1 {
		return userAgents[0]
	}
	if uaRandomize {
		return userAgents[rand.Intn(len(userAgents))]
	}
	uaMu.Lock()
	defer uaMu.Unlock()
	ua := userAgents[uaIndex%len(userAgents)]
	uaIndex++
	return ua
}

// ==================================================================
// Signature struct
// ==================================================================
type Signature struct {
	Name string
	Re   *regexp.Regexp
}

// ==================================================================
// LFI signatures
// ==================================================================
var lfiSignatures = []Signature{
	{"passwd-root", regexp.MustCompile(`root:[^:]*:0:0:`)},
	{"passwd-daemon", regexp.MustCompile(`daemon:[^:]*:[0-9]+:[0-9]+:`)},
	{"passwd-bin", regexp.MustCompile(`bin:[^:]*:[0-9]+:[0-9]+:/bin`)},
	{"passwd-nobody", regexp.MustCompile(`nobody:[^:]*:[0-9]+:[0-9]+:`)},
	{"shadow", regexp.MustCompile(`root:\$[0-9]+\$`)},
	{"linux-version", regexp.MustCompile(`Linux version \d`)},
	{"access-log", regexp.MustCompile(`HTTP/1\.[01]" [0-9]{3}`)},
	{"ssh-key", regexp.MustCompile(`BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY`)},
	{"environ", regexp.MustCompile(`PATH=.*HOME=.*USER=`)},
	{"uid-gid", regexp.MustCompile(`uid=[0-9]+\([^)]*\)\s+gid=[0-9]+`)},
	{"win.ini-fonts", regexp.MustCompile(`\[fonts\]`)},
	{"win.ini-16bit", regexp.MustCompile(`for 16-bit app support`)},
	{"win.ini-mci", regexp.MustCompile(`\[mci extensions\]`)},
	{"boot.ini", regexp.MustCompile(`\[boot loader\]`)},
	{"windows-hosts", regexp.MustCompile(`127\.0\.0\.1\s+localhost`)},
	{"php-base64", regexp.MustCompile(`PD9waHA`)},
	{"html-base64", regexp.MustCompile(`PGh0bWw`)},
	{"doctype-base64", regexp.MustCompile(`PCFET0NU`)},
	{"script-base64", regexp.MustCompile(`PHNjcmlwd`)},
}

// ==================================================================
// SSRF signatures
// ==================================================================
var ssrfSignatures = []Signature{
	{"passwd-root", regexp.MustCompile(`root:[^:]*:0:0:`)},
	{"apache-default", regexp.MustCompile(`<title>Apache2? (Ubuntu )?Default Page`)},
	{"nginx-version", regexp.MustCompile(`nginx/[0-9]+\.[0-9]+\.[0-9]+`)},
	{"nginx-welcome", regexp.MustCompile(`Welcome to nginx`)},
	{"iis-default", regexp.MustCompile(`Microsoft-IIS/[0-9]+\.[0-9]+`)},
	{"it-works", regexp.MustCompile(`It works!`)},
	{"aws-metadata", regexp.MustCompile(`(ami-id|instance-id|instance-type|local-ipv4|public-ipv4|security-credentials)`)},
	{"aws-accesskey", regexp.MustCompile(`AccessKeyId`)},
	{"aws-secret", regexp.MustCompile(`SecretAccessKey`)},
	{"gcp-metadata", regexp.MustCompile(`(computeMetadata|service-accounts|project-id)`)},
	{"gcp-token", regexp.MustCompile(`"access_token"`)},
	{"azure-vmid", regexp.MustCompile(`"vmId"`)},
	{"azure-subscription", regexp.MustCompile(`"subscriptionId"`)},
	{"azure-rg", regexp.MustCompile(`"resourceGroupName"`)},
	{"alibaba-meta", regexp.MustCompile(`(region-id|zone-id|private-ipv4)`)},
	{"do-droplet", regexp.MustCompile(`"droplet_id"|"vendor_data"`)},
	{"redis-info", regexp.MustCompile(`redis_version:`)},
	{"memcached", regexp.MustCompile(`STAT pid`)},
}

// ==================================================================
// CRLF signatures
// ==================================================================
var crlfHeaders = []Signature{
	{"crlf-location-evil", regexp.MustCompile(`(?i)location\s*:\s*(http[s]?:)?//?www\.evil\.com`)},
	{"crlf-set-cookie", regexp.MustCompile(`(?i)set-cookie\s*:\s*coffin\s*=\s*hi`)},
	{"crlf-coffin-x", regexp.MustCompile(`(?i)coffin-x\s*:\s*coffin-x`)},
}

var crlfStatuses = map[int]bool{
	200: true, 201: true, 202: true, 204: true, 205: true,
	206: true, 207: true, 301: true, 302: true, 307: true, 308: true,
}

// ==================================================================
// Open Redirect matcher
// ==================================================================
var orStatuses = map[int]bool{
	301: true, 302: true, 303: true, 307: true, 308: true,
}

var orLocationPattern = regexp.MustCompile(`(?im)^Location:\s*https?://bing\.com(?::\d+)?(?:[/?#\s]|$)`)

func matchOpenRedirect(status int, headers http.Header) ([]string, string) {
	if !orStatuses[status] {
		return nil, ""
	}
	loc := headers.Get("Location")
	if loc == "" {
		return nil, ""
	}
	if orLocationPattern.FindStringIndex("Location: "+loc) == nil {
		return nil, ""
	}
	proof := strings.TrimSpace("Location: " + loc)
	if len(proof) > 200 {
		proof = proof[:200]
	}
	return []string{"open-redirect-location-bing"}, proof
}

// ==================================================================
// XSS matcher (raw reflection)
// ==================================================================
func matchXSSReflection(body, payload string) ([]string, string) {
	if payload == "" {
		return nil, ""
	}
	needle := strings.TrimSpace(payload)
	if needle == "" {
		return nil, ""
	}
	idx := strings.Index(body, needle)
	if idx == -1 {
		return nil, ""
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + 40
	if end > len(body) {
		end = len(body)
	}
	proof := body[start:end]
	proof = strings.ReplaceAll(proof, "\r", " ")
	proof = strings.ReplaceAll(proof, "\n", " ")
	proof = strings.TrimSpace(proof)
	if len(proof) > 200 {
		proof = proof[:200]
	}
	return []string{"xss-reflected-raw"}, proof
}

// ==================================================================
// Matchers
// ==================================================================
func matchSignatureSet(sigs []Signature, body string) ([]string, string) {
	var found []string
	var proof string
	for _, s := range sigs {
		loc := s.Re.FindStringIndex(body)
		if loc == nil {
			continue
		}
		found = append(found, s.Name)
		if proof == "" {
			start := loc[0] - 20
			if start < 0 {
				start = 0
			}
			end := loc[1] + 100
			if end > len(body) {
				end = len(body)
			}
			raw := body[start:end]
			raw = strings.ReplaceAll(raw, "\r", " ")
			raw = strings.ReplaceAll(raw, "\n", " ")
			raw = strings.TrimSpace(raw)
			if len(raw) > 200 {
				raw = raw[:200]
			}
			proof = raw
		}
	}
	return found, proof
}

func headerToString(h http.Header) string {
	var sb strings.Builder
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\r\n")
		}
	}
	return sb.String()
}

func matchCRLFHeaders(status int, headers http.Header) ([]string, string) {
	if !crlfStatuses[status] {
		return nil, ""
	}
	hStr := headerToString(headers)
	var found []string
	var proof string
	for _, s := range crlfHeaders {
		loc := s.Re.FindStringIndex(hStr)
		if loc == nil {
			continue
		}
		found = append(found, s.Name)
		if proof == "" {
			start := loc[0] - 20
			if start < 0 {
				start = 0
			}
			end := loc[1] + 80
			if end > len(hStr) {
				end = len(hStr)
			}
			raw := strings.TrimSpace(hStr[start:end])
			raw = strings.ReplaceAll(raw, "\r", " ")
			raw = strings.ReplaceAll(raw, "\n", " ")
			if len(raw) > 200 {
				raw = raw[:200]
			}
			proof = raw
		}
	}
	return found, proof
}

// ==================================================================
// Loader
// ==================================================================
func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// ==================================================================
// URL helpers
// ==================================================================
func normalizeBase(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimRight(u, "/")
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	return u
}

func hasFuzz(s string) bool {
	return strings.Contains(s, fuzzPlaceholder)
}

func applyPayload(s, payload string) string {
	if s == "" {
		return s
	}
	return strings.ReplaceAll(s, fuzzPlaceholder, payload)
}

func replaceHostnameVar(s, base string) string {
	if !strings.Contains(s, "{{Hostname}}") {
		return s
	}
	u, err := url.Parse(base)
	if err != nil {
		return s
	}
	return strings.ReplaceAll(s, "{{Hostname}}", u.Host)
}

// ==================================================================
// HTTP
// ==================================================================
func buildClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        500,
			MaxIdleConnsPerHost: 100,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func sendRequest(method, rawURL string, headers map[string]string, body string) (int, string, http.Header, error) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, r)
	if err != nil {
		return 0, "", nil, err
	}

	if _, userSet := headers["User-Agent"]; !userSet {
		req.Header.Set("User-Agent", nextUA())
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", resp.Header, err
	}
	return resp.StatusCode, string(b), resp.Header, nil
}

// ==================================================================
// Finding
// ==================================================================
type Finding struct {
	Tag        string    `json:"tag"`
	URL        string    `json:"url"`
	Payload    string    `json:"payload,omitempty"`
	Status     int       `json:"status"`
	Signatures []string  `json:"signatures"`
	Proof      string    `json:"proof,omitempty"`
	Method     string    `json:"method"`
	FoundAt    time.Time `json:"found_at"`
}

func printFinding(f Finding) {
	printMu.Lock()
	defer printMu.Unlock()

	tagColor := cGreen
	switch f.Tag {
	case "crlf":
		tagColor = cMag
	case "ssrf":
		tagColor = cCyan
	case "openredirect":
		tagColor = cBlue
	case "xss":
		tagColor = cYellow
	}
	fmt.Printf("\n%s[+][%s] HIT%s\n", tagColor, strings.ToUpper(f.Tag), cReset)
	fmt.Printf("    Method     : %s\n", f.Method)
	if f.Payload != "" {
		fmt.Printf("    Payload    : %s%s%s\n", cMag, f.Payload, cReset)
	}
	fmt.Printf("    URL        : %s\n", f.URL)
	fmt.Printf("    Status     : %d\n", f.Status)
	fmt.Printf("    Signatures : %s%s%s\n", cYellow, strings.Join(f.Signatures, ", "), cReset)
	if f.Proof != "" {
		fmt.Printf("%s    Proof      : %s%s\n", cMag, f.Proof, cReset)
	}
}

// ==================================================================
// Scanners (dengan check reachedHitLimit())
// ==================================================================
func scanLFIFuzz(pattern string, payloads []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, payload := range payloads {
		if shouldStop() || reachedHitLimit() {
			return
		}
		finalURL := applyPayload(pattern, payload)
		finalBody := applyPayload(body, payload)

		finalHeaders := make(map[string]string, len(headers))
		for k, v := range headers {
			finalHeaders[k] = applyPayload(v, payload)
		}

		status, respBody, _, err := sendRequest(method, finalURL, finalHeaders, finalBody)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchSignatureSet(lfiSignatures, respBody)
		if len(sigs) > 0 {
			f := Finding{Tag: "lfi", URL: finalURL, Payload: payload, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

func scanLFINofuzz(base string, paths []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, p := range paths {
		if shouldStop() || reachedHitLimit() {
			return
		}
		var finalURL string
		switch {
		case strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://"):
			finalURL = p
		case strings.HasPrefix(p, "/"):
			finalURL = base + p
		default:
			finalURL = base + "/" + p
		}

		status, respBody, _, err := sendRequest(method, finalURL, headers, body)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchSignatureSet(lfiSignatures, respBody)
		if len(sigs) > 0 {
			f := Finding{Tag: "lfi", URL: finalURL, Payload: p, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

func scanSSRFFuzz(pattern string, payloads []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, payload := range payloads {
		if shouldStop() || reachedHitLimit() {
			return
		}
		finalURL := applyPayload(pattern, payload)
		finalBody := applyPayload(body, payload)

		finalHeaders := make(map[string]string, len(headers))
		for k, v := range headers {
			finalHeaders[k] = applyPayload(v, payload)
		}

		status, respBody, _, err := sendRequest(method, finalURL, finalHeaders, finalBody)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchSignatureSet(ssrfSignatures, respBody)
		if len(sigs) > 0 {
			f := Finding{Tag: "ssrf", URL: finalURL, Payload: payload, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

func scanSSRFNofuzz(base string, paths []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, p := range paths {
		if shouldStop() || reachedHitLimit() {
			return
		}
		p = replaceHostnameVar(p, base)

		var finalURL string
		switch {
		case strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://"):
			finalURL = p
		case strings.HasPrefix(p, "/"):
			finalURL = base + p
		default:
			finalURL = base + "/" + p
		}

		status, respBody, _, err := sendRequest(method, finalURL, headers, body)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchSignatureSet(ssrfSignatures, respBody)
		if len(sigs) > 0 {
			f := Finding{Tag: "ssrf", URL: finalURL, Payload: p, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

func scanCRLF(base string, paths []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, p := range paths {
		if shouldStop() || reachedHitLimit() {
			return
		}
		p = replaceHostnameVar(p, base)

		var finalURL string
		switch {
		case strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://"):
			finalURL = p
		case strings.HasPrefix(p, "/"):
			finalURL = base + p
		default:
			finalURL = base + "/" + p
		}

		status, _, respHeaders, err := sendRequest(method, finalURL, headers, body)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchCRLFHeaders(status, respHeaders)
		if len(sigs) > 0 {
			f := Finding{Tag: "crlf", URL: finalURL, Payload: p, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

func scanOpenRedirectFuzz(pattern string, payloads []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, payload := range payloads {
		if shouldStop() || reachedHitLimit() {
			return
		}
		finalURL := applyPayload(pattern, payload)
		finalBody := applyPayload(body, payload)

		finalHeaders := make(map[string]string, len(headers))
		for k, v := range headers {
			finalHeaders[k] = applyPayload(v, payload)
		}

		status, _, respHeaders, err := sendRequest(method, finalURL, finalHeaders, finalBody)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchOpenRedirect(status, respHeaders)
		if len(sigs) > 0 {
			f := Finding{Tag: "openredirect", URL: finalURL, Payload: payload, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

func scanOpenRedirectNofuzz(base string, paths []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, p := range paths {
		if shouldStop() || reachedHitLimit() {
			return
		}
		p = replaceHostnameVar(p, base)

		var finalURL string
		switch {
		case strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://"):
			finalURL = p
		case strings.HasPrefix(p, "/"):
			finalURL = base + p
		default:
			finalURL = base + "/" + p
		}

		status, _, respHeaders, err := sendRequest(method, finalURL, headers, body)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchOpenRedirect(status, respHeaders)
		if len(sigs) > 0 {
			f := Finding{Tag: "openredirect", URL: finalURL, Payload: p, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

func scanXSSFuzz(pattern string, payloads []string, method string, headers map[string]string, body string, onHit func(Finding)) {
	for _, payload := range payloads {
		if shouldStop() || reachedHitLimit() {
			return
		}
		finalURL := applyPayload(pattern, payload)
		finalBody := applyPayload(body, payload)

		finalHeaders := make(map[string]string, len(headers))
		for k, v := range headers {
			finalHeaders[k] = applyPayload(v, payload)
		}

		status, respBody, _, err := sendRequest(method, finalURL, finalHeaders, finalBody)
		atomic.AddInt64(&reqCount, 1)
		if err != nil {
			if verbose {
				printMu.Lock()
				fmt.Printf("%s[!] %s -> %v%s\n", cYellow, finalURL, err, cReset)
				printMu.Unlock()
			}
			continue
		}

		sigs, proof := matchXSSReflection(respBody, payload)
		if len(sigs) > 0 {
			f := Finding{Tag: "xss", URL: finalURL, Payload: payload, Status: status, Signatures: sigs, Proof: proof, Method: method, FoundAt: time.Now()}
			atomic.AddInt64(&hitCount, 1)
			printFinding(f)
			onHit(f)
		}
	}
}

// ==================================================================
// PoC writer
// ==================================================================
func writePoc(path string, findings []Finding) error {
	seen := map[string]bool{}
	var lines []string
	lines = append(lines, "# ChimeraScan PoC - "+time.Now().Format("2006-01-02 15:04:05"))
	if interrupted {
		lines = append(lines, "# NOTE: scan was interrupted by user (Ctrl+C) — partial results")
	}
	if hitLimit > 0 {
		lines = append(lines, fmt.Sprintf("# NOTE: scan stopped after reaching -hit=%d", hitLimit))
	}
	lines = append(lines, "# Format: [TAG] URL")
	lines = append(lines, "")

	for _, f := range findings {
		key := f.Tag + "|" + f.URL
		if seen[key] {
			continue
		}
		seen[key] = true
		lines = append(lines, fmt.Sprintf("[%s] %s", strings.ToUpper(f.Tag), f.URL))
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// ==================================================================
// Main
// ==================================================================
type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func parseHeaders(raw []string) map[string]string {
	m := map[string]string{}
	for _, h := range raw {
		idx := strings.Index(h, ":")
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(h[:idx])
		v := strings.TrimSpace(h[idx+1:])
		if k != "" {
			m[k] = v
		}
	}
	return m
}

func parseTags(raw string) map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(strings.ToLower(t))
		if t != "" {
			m[t] = true
		}
	}
	return m
}

func printBanner() {
	fmt.Println(cBlue + strings.Repeat("=", 70) + cReset)
	fmt.Println(cBold + "  " + cCyan + "ChimeraScan" + cReset + cBold + "  —  LFI · CRLF · SSRF · Open Redirect · XSS" + cReset)
	fmt.Println(cDim + "  Penta-threat web vulnerability fuzzer" + cReset)
	fmt.Println(cBlue + strings.Repeat("=", 70) + cReset)
}

func tagsFlagLine(raw string, runLFI, runCRLF, runSSRF, runOR, runXSS bool) string {
	if strings.TrimSpace(raw) == "" {
		return "lfi, crlf, ssrf, openredirect, xss"
	}
	parts := []string{}
	if runLFI {
		parts = append(parts, "lfi")
	}
	if runCRLF {
		parts = append(parts, "crlf")
	}
	if runSSRF {
		parts = append(parts, "ssrf")
	}
	if runOR {
		parts = append(parts, "openredirect")
	}
	if runXSS {
		parts = append(parts, "xss")
	}
	return strings.Join(parts, ", ")
}

func main() {
	var (
		urlFlag    string
		listFlag   string
		tagsFlag   string
		outFlag    string
		method     string
		bodyFlag   string
		fuzzFlag   bool
		threads    int
		timeoutS   int
		verboseF   bool
		hitFlag    int
		pocFlag    bool
		uaFileFlag string
		uaRandFlag bool
	)
	var headersFlag headerList

	flag.StringVar(&urlFlag, "u", "", "Base URL (e.g. https://example.com)")
	flag.StringVar(&listFlag, "l", "", "File with list of base URLs (one per line)")
	flag.StringVar(&tagsFlag, "tags", "", "Modules: lfi, crlf, ssrf, openredirect, xss (empty = all)")
	flag.BoolVar(&fuzzFlag, "fuzz", false, "Enable fuzzing (replace FUZZ). LFI, SSRF, Open Redirect & XSS. CRLF is always nofuzz")
	flag.IntVar(&hitFlag, "hit", 0, "Stop after N vulnerable findings (0 = scan all payloads, default: 0)")
	flag.BoolVar(&pocFlag, "poc", false, "Auto-save hitting URLs to poc.txt")
	flag.StringVar(&outFlag, "o", "", "Save findings to JSON")
	flag.StringVar(&method, "X", "GET", "HTTP method")
	flag.StringVar(&bodyFlag, "d", "", "Request body (may contain FUZZ)")
	flag.Var(&headersFlag, "H", "Header 'Name: value' (repeatable)")
	flag.IntVar(&threads, "T", 20, "Concurrent threads")
	flag.IntVar(&timeoutS, "timeout", 15, "Request timeout (seconds)")
	flag.BoolVar(&verboseF, "v", false, "Verbose")
	flag.StringVar(&uaFileFlag, "ua", defaultUAFile, "User-Agent list file (one UA per line)")
	flag.BoolVar(&uaRandFlag, "ua-random", false, "Pick random UA per request (default: round-robin)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ChimeraScan — Penta-threat web vulnerability fuzzer\n")
		fmt.Fprintf(os.Stderr, "(LFI | CRLF | SSRF | Open Redirect | XSS)\n\n")
		fmt.Fprintf(os.Stderr, "Structure:\n")
		fmt.Fprintf(os.Stderr, "  Ua.txt                              -> User-Agent list (one per line)\n")
		fmt.Fprintf(os.Stderr, "  lfi/fuzzing/payload.txt             -> payload only (replace FUZZ)\n")
		fmt.Fprintf(os.Stderr, "  lfi/nofuzz/payload.txt              -> full path/query\n")
		fmt.Fprintf(os.Stderr, "  crlf/payload.txt                    -> full path (CRLF)\n")
		fmt.Fprintf(os.Stderr, "  ssrf/fuzzing/payload.txt            -> URL only (replace FUZZ)\n")
		fmt.Fprintf(os.Stderr, "  ssrf/nofuzz/payload.txt             -> full path/query\n")
		fmt.Fprintf(os.Stderr, "  openredirect/fuzzing/payload.txt    -> URL only (replace FUZZ)\n")
		fmt.Fprintf(os.Stderr, "  openredirect/nofuzz/payload.txt     -> full path/query\n")
		fmt.Fprintf(os.Stderr, "  xss/fuzzing/payload.txt             -> payload only (XSS = FUZZ only)\n\n")
		fmt.Fprintf(os.Stderr, "Hit limit behaviour:\n")
		fmt.Fprintf(os.Stderr, "  -hit=2       -> stop after 2 vulnerable findings\n")
		fmt.Fprintf(os.Stderr, "  -hit=1       -> stop after first finding\n")
		fmt.Fprintf(os.Stderr, "  (no -hit)    -> scan ALL payloads (default)\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  %s -u 'https://example.com/?q=FUZZ' -tags xss -fuzz\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u 'https://example.com/?q=FUZZ' -tags xss -fuzz -hit=2\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u https://example.com -tags lfi,ssrf\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u https://example.com -tags lfi,ssrf,openredirect,xss -fuzz -poc\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u https://example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "      -> all modules (XSS skipped unless -fuzz)\n\n")
		fmt.Fprintf(os.Stderr, "Ctrl+C: press once to stop & save PoC, twice to force exit.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	verbose = verboseF
	hitLimit = hitFlag
	if hitLimit < 0 {
		hitLimit = 0
	}
	headers := parseHeaders(headersFlag)
	uaRandomize = uaRandFlag

	loadUserAgents(uaFileFlag)

	if (urlFlag == "") == (listFlag == "") {
		fmt.Println(cRed + "[!] Choose one: -u URL or -l FILE" + cReset)
		flag.Usage()
		os.Exit(1)
	}

	// ---- Tags ----
	tags := parseTags(tagsFlag)
	runAll := len(tags) == 0
	runLFI := runAll || tags["lfi"]
	runCRLF := runAll || tags["crlf"]
	runSSRF := runAll || tags["ssrf"]
	runOR := runAll || tags["openredirect"]
	runXSS := runAll || tags["xss"]

	if !runLFI && !runCRLF && !runSSRF && !runOR && !runXSS {
		fmt.Printf("%s[!] Unknown tag: %s (only: lfi, crlf, ssrf, openredirect, xss)%s\n",
			cRed, tagsFlag, cReset)
		os.Exit(1)
	}

	// ---- XSS: fuzz only ----
	if runXSS && !fuzzFlag {
		if tags["xss"] && len(tags) == 1 {
			fmt.Printf("%s[!] XSS module requires -fuzz flag. Re-run with: -tags xss -fuzz%s\n",
				cRed, cReset)
			os.Exit(1)
		}
		runXSS = false
	}

	// ---- Base URLs ----
	var bases []string
	if urlFlag != "" {
		bases = []string{urlFlag}
	} else {
		var err error
		bases, err = loadLines(listFlag)
		if err != nil {
			fmt.Printf("%s[!] Failed to load URL list: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
	}
	if len(bases) == 0 {
		fmt.Println(cRed + "[!] No targets." + cReset)
		os.Exit(1)
	}
	for i, b := range bases {
		bases[i] = normalizeBase(b)
	}

	// ---- Load payloads ----
	var (
		lfiPayloads  []string
		lfiFile      string
		ssrfPayloads []string
		ssrfFile     string
		crlfPayloads []string
		orPayloads   []string
		orFile       string
		xssPayloads  []string
	)

	if runLFI {
		if fuzzFlag {
			lfiFile = lfiFuzzFile
		} else {
			lfiFile = lfiNofuzzFile
		}
		var err error
		lfiPayloads, err = loadLines(lfiFile)
		if err != nil {
			fmt.Printf("%s[!] Failed to load %s: %v%s\n", cRed, lfiFile, err, cReset)
			os.Exit(1)
		}
		if len(lfiPayloads) == 0 {
			fmt.Printf("%s[!] File %s is empty%s\n", cRed, lfiFile, cReset)
			os.Exit(1)
		}
	}

	if runSSRF {
		if fuzzFlag {
			ssrfFile = ssrfFuzzFile
		} else {
			ssrfFile = ssrfNofuzzFile
		}
		var err error
		ssrfPayloads, err = loadLines(ssrfFile)
		if err != nil {
			fmt.Printf("%s[!] Failed to load %s: %v%s\n", cRed, ssrfFile, err, cReset)
			os.Exit(1)
		}
		if len(ssrfPayloads) == 0 {
			fmt.Printf("%s[!] File %s is empty%s\n", cRed, ssrfFile, cReset)
			os.Exit(1)
		}
	}

	if runCRLF {
		var err error
		crlfPayloads, err = loadLines(crlfFile)
		if err != nil {
			fmt.Printf("%s[!] Failed to load %s: %v%s\n", cRed, crlfFile, err, cReset)
			os.Exit(1)
		}
		if len(crlfPayloads) == 0 {
			fmt.Printf("%s[!] File %s is empty%s\n", cRed, crlfFile, cReset)
			os.Exit(1)
		}
	}

	if runOR {
		if fuzzFlag {
			orFile = orFuzzFile
		} else {
			orFile = orNofuzzFile
		}
		var err error
		orPayloads, err = loadLines(orFile)
		if err != nil {
			fmt.Printf("%s[!] Failed to load %s: %v%s\n", cRed, orFile, err, cReset)
			os.Exit(1)
		}
		if len(orPayloads) == 0 {
			fmt.Printf("%s[!] File %s is empty%s\n", cRed, orFile, cReset)
			os.Exit(1)
		}
	}

	if runXSS {
		var err error
		xssPayloads, err = loadLines(xssFuzzFile)
		if err != nil {
			fmt.Printf("%s[!] Failed to load %s: %v%s\n", cRed, xssFuzzFile, err, cReset)
			os.Exit(1)
		}
		if len(xssPayloads) == 0 {
			fmt.Printf("%s[!] File %s is empty%s\n", cRed, xssFuzzFile, cReset)
			os.Exit(1)
		}
	}

	// ---- Fuzzing validation ----
	if fuzzFlag && (runLFI || runSSRF || runOR || runXSS) {
		headersJoined := strings.Join(headersFlag, " ")
		found := false
		for _, b := range bases {
			if hasFuzz(b) {
				found = true
				break
			}
		}
		if !found && !hasFuzz(bodyFlag) && !hasFuzz(headersJoined) {
			fmt.Printf("%s[!] -fuzz is active but placeholder %q not found in URL/body/header.\n",
				cRed, fuzzPlaceholder, cReset)
			fmt.Printf("%s    Example: -u 'https://example.com/?q=%s' -tags xss -fuzz\n",
				cYellow, fuzzPlaceholder, cReset)
			os.Exit(1)
		}
	}

	// ---- Setup ----
	timeout := time.Duration(timeoutS) * time.Second
	httpClient = buildClient(timeout)

	// ---- Banner ----
	printBanner()

	modeLFI := "OFF"
	if runLFI {
		if fuzzFlag {
			modeLFI = "FUZZ (placeholder=" + fuzzPlaceholder + ")"
		} else {
			modeLFI = "NOFUZZ"
		}
	}
	modeSSRF := "OFF"
	if runSSRF {
		if fuzzFlag {
			modeSSRF = "FUZZ (placeholder=" + fuzzPlaceholder + ")"
		} else {
			modeSSRF = "NOFUZZ"
		}
	}
	modeCRLF := "OFF"
	if runCRLF {
		modeCRLF = "NOFUZZ"
	}
	modeOR := "OFF"
	if runOR {
		if fuzzFlag {
			modeOR = "FUZZ (placeholder=" + fuzzPlaceholder + ")"
		} else {
			modeOR = "NOFUZZ"
		}
	}
	modeXSS := "OFF"
	if runXSS {
		modeXSS = "FUZZ (placeholder=" + fuzzPlaceholder + ")"
	}

	uaMode := "round-robin"
	if uaRandomize {
		uaMode = "random"
	}

	fmt.Printf("%s[*] Tags        : %s%s%s\n", cCyan, cBold, tagsFlagLine(tagsFlag, runLFI, runCRLF, runSSRF, runOR, runXSS), cReset)
	fmt.Printf("%s[*] Mode LFI    : %s%s%s\n", cCyan, cGreen, modeLFI, cReset)
	fmt.Printf("%s[*] Mode SSRF   : %s%s%s\n", cCyan, cCyan, modeSSRF, cReset)
	fmt.Printf("%s[*] Mode CRLF   : %s%s%s\n", cCyan, cMag, modeCRLF, cReset)
	fmt.Printf("%s[*] Mode OR     : %s%s%s\n", cCyan, cBlue, modeOR, cReset)
	fmt.Printf("%s[*] Mode XSS    : %s%s%s\n", cCyan, cYellow, modeXSS, cReset)
	if tags["xss"] && !runXSS {
		fmt.Printf("%s[*] Note        : XSS skipped (requires -fuzz)%s\n", cDim, cReset)
	}
	fmt.Printf("%s[*] Bases       : %d%s\n", cCyan, len(bases), cReset)
	if runLFI {
		fmt.Printf("%s[*] LFI src     : %s (%d item)%s\n", cCyan, lfiFile, len(lfiPayloads), cReset)
	}
	if runSSRF {
		fmt.Printf("%s[*] SSRF src    : %s (%d item)%s\n", cCyan, ssrfFile, len(ssrfPayloads), cReset)
	}
	if runCRLF {
		fmt.Printf("%s[*] CRLF src    : %s (%d item)%s\n", cCyan, crlfFile, len(crlfPayloads), cReset)
	}
	if runOR {
		fmt.Printf("%s[*] OR src      : %s (%d item)%s\n", cCyan, orFile, len(orPayloads), cReset)
	}
	if runXSS {
		fmt.Printf("%s[*] XSS src     : %s (%d item)%s\n", cCyan, xssFuzzFile, len(xssPayloads), cReset)
	}
	fmt.Printf("%s[*] User-Agent  : %d loaded (mode=%s) [%s]%s\n",
		cCyan, len(userAgents), uaMode, uaFileFlag, cReset)
	fmt.Printf("%s[*] Method      : %s%s\n", cCyan, strings.ToUpper(method), cReset)
	fmt.Printf("%s[*] Threads     : %d   Timeout: %ds%s\n", cCyan, threads, timeoutS, cReset)

	if hitLimit > 0 {
		fmt.Printf("%s[*] Hit limit   : %s%d%s (stop after %d finding(s))\n",
			cCyan, cYellow, hitLimit, hitLimit, cReset)
	} else {
		fmt.Printf("%s[*] Hit limit   : %s∞ (scan all payloads)%s\n",
			cCyan, cGreen, cReset)
	}
	fmt.Printf("%s[*] Ctrl+C      : once = save & stop, twice = force exit%s\n", cDim, cReset)
	fmt.Println(cBlue + strings.Repeat("-", 70) + cReset)

	// ---- Scan ----
	var (
		mu       sync.Mutex
		findings []Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, threads)
		done     int64
	)

	totalTasks := len(bases)
	start := time.Now()

	onHit := func(f Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	stopTicker := make(chan struct{})
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopTicker:
				return
			case <-t.C:
				if shouldStop() || reachedHitLimit() {
					return
				}
				d := atomic.LoadInt64(&done)
				r := atomic.LoadInt64(&reqCount)
				h := atomic.LoadInt64(&hitCount)
				printMu.Lock()
				fmt.Printf("%s[i] %d/%d targets | %d requests | hits: %d%s\n",
					cDim, d, totalTasks, r, h, cReset)
				printMu.Unlock()
			}
		}
	}()

	for _, b := range bases {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() {
				<-sem
				atomic.AddInt64(&done, 1)
			}()

			if shouldStop() || reachedHitLimit() {
				return
			}
			if runLFI {
				if fuzzFlag {
					scanLFIFuzz(target, lfiPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
				} else {
					scanLFINofuzz(target, lfiPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
				}
			}

			if shouldStop() || reachedHitLimit() {
				return
			}
			if runSSRF {
				if fuzzFlag {
					scanSSRFFuzz(target, ssrfPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
				} else {
					scanSSRFNofuzz(target, ssrfPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
				}
			}

			if shouldStop() || reachedHitLimit() {
				return
			}
			if runCRLF {
				scanCRLF(target, crlfPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
			}

			if shouldStop() || reachedHitLimit() {
				return
			}
			if runOR {
				if fuzzFlag {
					scanOpenRedirectFuzz(target, orPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
				} else {
					scanOpenRedirectNofuzz(target, orPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
				}
			}

			if shouldStop() || reachedHitLimit() {
				return
			}
			if runXSS {
				scanXSSFuzz(target, xssPayloads, strings.ToUpper(method), headers, bodyFlag, onHit)
			}
		}(b)
	}

	wg.Wait()
	close(stopTicker)

	elapsed := time.Since(start)

	// ---- Summary ----
	fmt.Println()
	fmt.Println(cBlue + strings.Repeat("=", 70) + cReset)

	finalHits := atomic.LoadInt64(&hitCount)

	if interrupted {
		fmt.Printf("%s[!] Interrupted.%s  Bases: %d  |  Requests: %d  |  Hits: %d  |  Time: %s\n",
			cYellow, cReset, len(bases),
			atomic.LoadInt64(&reqCount),
			finalHits,
			elapsed.Round(time.Millisecond))
		fmt.Printf("%s    (partial results — PoC was still saved)%s\n", cDim, cReset)
	} else if hitLimit > 0 && finalHits >= int64(hitLimit) {
		fmt.Printf("%s[=] Done (hit limit reached).%s  Bases: %d  |  Requests: %d  |  Hits: %d  |  Time: %s\n",
			cBold, cReset, len(bases),
			atomic.LoadInt64(&reqCount),
			finalHits,
			elapsed.Round(time.Millisecond))
		fmt.Printf("%s    Reached -hit=%d limit — scan stopped early.%s\n", cDim, hitLimit, cReset)
	} else {
		fmt.Printf("%s[=] Done.%s  Bases: %d  |  Requests: %d  |  Hits: %d  |  Time: %s\n",
			cBold, cReset, len(bases),
			atomic.LoadInt64(&reqCount),
			finalHits,
			elapsed.Round(time.Millisecond))
	}
	fmt.Println(cBlue + strings.Repeat("=", 70) + cReset)

	// ---- Outputs ----
	if pocFlag && len(findings) > 0 {
		if err := writePoc(defaultPocFile, findings); err != nil {
			fmt.Printf("%s[!] Failed to write PoC: %v%s\n", cRed, err, cReset)
		} else {
			fmt.Printf("%s[*] PoC saved  : %s (%d URL)%s\n",
				cCyan, defaultPocFile, len(findings), cReset)
		}
	}

	if outFlag != "" && len(findings) > 0 {
		data, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			fmt.Printf("%s[!] Marshal error: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
		if err := os.WriteFile(outFlag, data, 0644); err != nil {
			fmt.Printf("%s[!] Write error: %v%s\n", cRed, err, cReset)
			os.Exit(1)
		}
		fmt.Printf("%s[*] JSON saved : %s%s\n", cCyan, outFlag, cReset)
	}
}