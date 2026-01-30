package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Target struct {
	Group  string `json:"group"`
	URL    string `json:"url"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
}

type ProbeResult struct {
	Group    string   `json:"group"`
	Name     string   `json:"name"`
	URL      string   `json:"url"`
	Host     string   `json:"host"`
	DNSOK    bool     `json:"dns_ok"`
	DNSAddrs []string `json:"dns_addrs"`

	ChosenIP string `json:"chosen_ip,omitempty"`
	IPFamily string `json:"ip_family,omitempty"`

	TCP443OK bool `json:"tcp443_ok"`
	TLSOK    bool `json:"tls_ok"`

	HTTPOK     bool   `json:"http_ok"`
	HTTPCode   int    `json:"http_code,omitempty"`
	HTTPMethod string `json:"http_method,omitempty"`
	LatencyMS  int    `json:"latency_ms,omitempty"`

	Err string `json:"err,omitempty"`
}

type GroupSummary struct {
	Total        int `json:"total"`
	HTTP_OK      int `json:"http_ok"`
	DNS_OK       int `json:"dns_ok"`
	TCP_OK       int `json:"tcp_ok"`
	TLS_OK       int `json:"tls_ok"`
	Timeouts     int `json:"timeouts"`
	TLSVerifyErr int `json:"tls_verify_errors"`
	OtherErr     int `json:"other_errors"`
}

type Output struct {
	TS      string                  `json:"ts"`
	Status  string                  `json:"status"`
	Verdict string                  `json:"verdict"`
	Summary map[string]GroupSummary `json:"group_summary"`
	Results []ProbeResult           `json:"results"`
}

func nowISO() string { return time.Now().Format("2006-01-02T15:04:05") }

func isFilteredGroup(g string) bool {
	return strings.EqualFold(strings.TrimSpace(g), "filtered")
}

/*
targets.txt format:
  group url [label]
Examples:
  core https://www.google.com/generate_204 google_204
  domestic https://www.aparat.com aparat
  filtered https://twitter.com twitter

If group missing: group="default"
If label missing: label=hostname
*/
func loadTargets(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Target
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		group := "default"
		rawURL := ""
		label := ""

		if len(parts) >= 3 {
			group, rawURL, label = parts[0], parts[1], parts[2]
		} else if len(parts) == 2 {
			if strings.Contains(parts[1], "://") && !strings.Contains(parts[0], "://") {
				group, rawURL = parts[0], parts[1]
			} else {
				rawURL, label = parts[0], parts[1]
			}
		} else {
			rawURL = parts[0]
		}

		pu, err := url.Parse(rawURL)
		if err != nil || pu.Hostname() == "" {
			return nil, fmt.Errorf("invalid url in targets: %q", rawURL)
		}

		host := pu.Hostname()
		scheme := pu.Scheme
		if scheme == "" {
			scheme = "https"
		}
		if label == "" {
			label = host
		}

		out = append(out, Target{
			Group: group, URL: rawURL, Name: label, Host: host, Scheme: scheme,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets found in %s", path)
	}
	return out, nil
}

func dnsLookup(host string, timeout time.Duration) (bool, []string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false, nil, "dns:" + err.Error()
	}

	uniq := map[string]struct{}{}
	for _, ip := range ips {
		uniq[ip.IP.String()] = struct{}{}
	}

	var addrs []string
	for s := range uniq {
		addrs = append(addrs, s)
	}
	sort.Strings(addrs)
	return len(addrs) > 0, addrs, ""
}

func orderIPs(addrs []string, ipv4Only bool) []string {
	v4 := []string{}
	v6 := []string{}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	if ipv4Only {
		return v4
	}
	return append(v4, v6...)
}

func ipFamily(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "v4"
	}
	return "v6"
}

func tcpConnect(ip string, timeout time.Duration) (bool, string) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false, "tcp:" + err.Error()
	}
	_ = conn.Close()
	return true, ""
}

func tlsHandshake(host, ip string, timeout time.Duration) (bool, string) {
	d := net.Dialer{Timeout: timeout}
	cfg := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	conn, err := tls.DialWithDialer(&d, "tcp", net.JoinHostPort(ip, "443"), cfg)
	if err != nil {
		return false, "tls:" + err.Error()
	}
	_ = conn.Close()
	return true, ""
}

func chooseReachableIP(orderedIPs []string, timeout time.Duration) (chosen, family string, ok bool, err string) {
	lastErr := ""
	for _, ip := range orderedIPs {
		tok, terr := tcpConnect(ip, timeout)
		if tok {
			return ip, ipFamily(ip), true, ""
		}
		lastErr = terr
	}
	return "", "", false, lastErr
}

// Shared HTTP client (safe for concurrent use)
func makeHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        100,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// httpDo returns ok=true if status is 2xx/3xx.
// If not ok and no transport error, err will be "http:METHOD status=XYZ".
func httpDo(client *http.Client, method, rawURL string, timeout time.Duration) (ok bool, code int, latMS int, err string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, e := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if e != nil {
		return false, 0, 0, "http:" + e.Error()
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) net-health/2.4")
	req.Header.Set("Accept", "*/*")

	t0 := time.Now()
	resp, e := client.Do(req)
	lat := int(time.Since(t0).Milliseconds())

	if e != nil {
		return false, 0, lat, "http:" + e.Error()
	}
	defer resp.Body.Close()

	code = resp.StatusCode
	ok = code >= 200 && code < 400
	if ok {
		return true, code, lat, ""
	}
	return false, code, lat, fmt.Sprintf("http:%s status=%d", method, code)
}

// HEAD first; fallback to GET.
func httpFetchSmart(client *http.Client, rawURL string, timeout time.Duration) (ok bool, code int, lat int, method string, err string) {
	okH, codeH, latH, errH := httpDo(client, "HEAD", rawURL, timeout)
	if okH {
		return true, codeH, latH, "HEAD", ""
	}

	okG, codeG, latG, errG := httpDo(client, "GET", rawURL, timeout)
	if okG {
		return true, codeG, latG, "GET", ""
	}
	if errG != "" {
		return false, codeG, latG, "GET", errG
	}
	return false, codeH, latH, "HEAD", errH
}

func summarizeByGroup(results []ProbeResult) map[string]GroupSummary {
	out := map[string]GroupSummary{}
	for _, r := range results {
		g := r.Group
		s := out[g]
		s.Total++

		if r.DNSOK {
			s.DNS_OK++
		}
		if r.TCP443OK {
			s.TCP_OK++
		}
		if r.TLSOK {
			s.TLS_OK++
		}
		if r.HTTPOK {
			s.HTTP_OK++
		}

		if strings.Contains(r.Err, "x509:") || strings.Contains(r.Err, "failed to verify certificate") {
			s.TLSVerifyErr++
		} else if strings.Contains(r.Err, "context deadline exceeded") ||
			strings.Contains(r.Err, "Client.Timeout") ||
			strings.Contains(r.Err, "i/o timeout") {
			s.Timeouts++
		} else if r.Err != "" {
			s.OtherErr++
		}
		out[g] = s
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// classifyStatus ignores "filtered" group in overall score.
// But if ANY filtered target becomes HTTPOK, we append a strong alert.
func classifyStatus(results []ProbeResult, groups map[string]GroupSummary) (status, verdict string) {
	// base (non-filtered) totals
	total := 0
	httpOK := 0
	dnsOK := 0
	tlsVerifyErr := 0
	timeouts := 0

	// filtered stats
	fTotal := 0
	fHTTP := 0

	for _, r := range results {
		if isFilteredGroup(r.Group) {
			fTotal++
			if r.HTTPOK {
				fHTTP++
			}
			continue
		}

		total++
		if r.HTTPOK {
			httpOK++
		}
		if r.DNSOK {
			dnsOK++
		}
		if strings.Contains(r.Err, "x509:") || strings.Contains(r.Err, "failed to verify certificate") {
			tlsVerifyErr++
		}
		if strings.Contains(r.Err, "context deadline exceeded") ||
			strings.Contains(r.Err, "Client.Timeout") ||
			strings.Contains(r.Err, "i/o timeout") {
			timeouts++
		}
	}

	if total == 0 {
		// edge case: only filtered targets provided
		status = "ONLY_FILTERED_TARGETS"
		verdict = fmt.Sprintf("0/0 non-filtered (ignored) | filtered_open=%d/%d", fHTTP, fTotal)
		if fHTTP > 0 {
			verdict += " | ALERT_FILTERED_OPEN"
		}
		return status, verdict
	}

	dom := groups["domestic"]
	intl := groups["intl"]
	dev := groups["dev"]
	cloud := groups["cloud"]
	cdn := groups["cdn"]
	core := groups["core"]

	coreOK := core.HTTP_OK
	outerTotal := intl.Total + dev.Total + cloud.Total + cdn.Total
	outerOK := intl.HTTP_OK + dev.HTTP_OK + cloud.HTTP_OK + cdn.HTTP_OK

	domOnly := dom.Total > 0 && dom.HTTP_OK >= max(1, dom.Total/2) && outerTotal > 0 && outerOK == 0
	walledGarden := core.Total > 0 && coreOK > 0 && outerTotal > 0 && outerOK <= max(1, outerTotal/6)

	if dnsOK == 0 {
		status = "DOWN_OR_DNS_BLOCKED"
		verdict = "no DNS + no HTTP (non-filtered)"
	} else if httpOK == 0 {
		status = "NO_HTTP_CONNECTIVITY"
		verdict = "DNS ok but HTTP all failed (non-filtered)"
	} else if domOnly {
		status = "DOMESTIC_ONLY"
		verdict = fmt.Sprintf("domestic ok (%d/%d) but intl/dev/cloud/cdn all failed", dom.HTTP_OK, dom.Total)
	} else if walledGarden {
		status = "WALLED_GARDEN_LIKELY"
		verdict = fmt.Sprintf("core ok (%d/%d) but intl/dev/cloud/cdn mostly blocked (%d/%d)", core.HTTP_OK, core.Total, outerOK, outerTotal)
	} else if httpOK < max(2, total/2) {
		status = "PARTIAL_CONNECTIVITY"
		verdict = fmt.Sprintf("%d/%d non-filtered targets ok", httpOK, total)
	} else {
		status = "OK_MOSTLY"
		verdict = fmt.Sprintf("%d/%d non-filtered targets ok", httpOK, total)
	}

	if tlsVerifyErr >= 2 || (tlsVerifyErr >= 1 && total <= 10) {
		verdict += " | POSSIBLE_MITM_OR_DNS_HIJACK (TLS verify errors)"
	}
	if timeouts >= max(2, total/4) {
		verdict += " | HIGH_LATENCY_OR_RATE_LIMIT (many timeouts)"
	}

	// filtered is ignored in score, but we report if it opens
	if fTotal > 0 {
		verdict += fmt.Sprintf(" | filtered_open=%d/%d (ignored)", fHTTP, fTotal)
		if fHTTP > 0 {
			verdict += " | ALERT_FILTERED_OPEN"
		}
	}

	return status, verdict
}

func printGroupSummary(groups map[string]GroupSummary) {
	order := []string{"core", "cdn", "cloud", "dc", "dev", "intl", "domestic", "filtered", "default"}
	seen := map[string]bool{}

	fmt.Println("== group summary ==")
	for _, g := range order {
		s, ok := groups[g]
		if !ok || s.Total == 0 {
			continue
		}
		seen[g] = true

		tag := ""
		if isFilteredGroup(g) {
			tag = " (ignored in score)"
		}

		fmt.Printf(" - %-9s ok=%d/%d dns=%d tcp=%d tls=%d timeouts=%d tls_verify=%d other_err=%d%s\n",
			g, s.HTTP_OK, s.Total, s.DNS_OK, s.TCP_OK, s.TLS_OK, s.Timeouts, s.TLSVerifyErr, s.OtherErr, tag)
	}

	var extras []string
	for g := range groups {
		if !seen[g] {
			extras = append(extras, g)
		}
	}
	sort.Strings(extras)
	for _, g := range extras {
		s := groups[g]
		if s.Total == 0 {
			continue
		}
		tag := ""
		if isFilteredGroup(g) {
			tag = " (ignored in score)"
		}
		fmt.Printf(" - %-9s ok=%d/%d dns=%d tcp=%d tls=%d timeouts=%d tls_verify=%d other_err=%d%s\n",
			g, s.HTTP_OK, s.Total, s.DNS_OK, s.TCP_OK, s.TLS_OK, s.Timeouts, s.TLSVerifyErr, s.OtherErr, tag)
	}
}

func icon(ok bool) string {
	if ok {
		return "✅"
	}
	return "❌"
}

// probeOne runs full probe for one target.
func probeOne(t Target, timeout time.Duration, ipv4Only bool, httpClient *http.Client) ProbeResult {
	r := ProbeResult{Group: t.Group, Name: t.Name, URL: t.URL, Host: t.Host}

	dnsOK, addrs, dnsErr := dnsLookup(t.Host, timeout)
	r.DNSOK = dnsOK
	r.DNSAddrs = addrs
	if !dnsOK {
		r.Err = dnsErr
		return r
	}

	ordered := orderIPs(addrs, ipv4Only)
	chosen, fam, ok, chooseErr := chooseReachableIP(ordered, timeout)
	r.ChosenIP = chosen
	r.IPFamily = fam
	r.TCP443OK = ok
	if !ok {
		r.Err = chooseErr
		return r
	}

	tlsOK, tlsErr := tlsHandshake(t.Host, chosen, timeout)
	r.TLSOK = tlsOK
	if !tlsOK {
		r.Err = tlsErr
	}

	httpOK, code, lat, method, httpErr := httpFetchSmart(httpClient, t.URL, timeout)
	r.HTTPOK = httpOK
	r.HTTPCode = code
	r.LatencyMS = lat
	r.HTTPMethod = method
	if !httpOK && r.Err == "" {
		r.Err = httpErr
	}

	return r
}

func main() {
	var targetsPath string
	var timeoutSec float64
	var jsonOut bool
	var loop bool
	var intervalSec int
	var ipv4Only bool
	var concurrency int

	flag.StringVar(&targetsPath, "targets", "targets.txt", "path to targets file")
	flag.Float64Var(&timeoutSec, "timeout", 3.0, "timeout seconds per check")
	flag.BoolVar(&jsonOut, "json", false, "output JSON")
	flag.BoolVar(&loop, "loop", false, "run continuously")
	flag.IntVar(&intervalSec, "interval", 30, "seconds between runs (when --loop)")
	flag.BoolVar(&ipv4Only, "ipv4-only", false, "skip IPv6 entirely")
	flag.IntVar(&concurrency, "concurrency", 8, "number of parallel probes")
	flag.Parse()

	targets, err := loadTargets(targetsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}

	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(targets) {
		concurrency = len(targets)
	}

	timeout := time.Duration(timeoutSec * float64(time.Second))
	httpClient := makeHTTPClient()

	runOnce := func() {
		results := make([]ProbeResult, len(targets))

		idxCh := make(chan int)
		var wg sync.WaitGroup
		wg.Add(concurrency)

		for w := 0; w < concurrency; w++ {
			go func() {
				defer wg.Done()
				for i := range idxCh {
					results[i] = probeOne(targets[i], timeout, ipv4Only, httpClient)
				}
			}()
		}

		for i := range targets {
			idxCh <- i
		}
		close(idxCh)
		wg.Wait()

		groups := summarizeByGroup(results)
		status, verdict := classifyStatus(results, groups)

		// Big alert if filtered opened
		if s, ok := groups["filtered"]; ok && s.Total > 0 && s.HTTP_OK > 0 {
			fmt.Printf("\n🚨🚨🚨 ALERT: FILTERED TARGETS ARE REACHABLE (%d/%d) 🚨🚨🚨\n", s.HTTP_OK, s.Total)
			fmt.Println("🚨 This is unexpected. Double-check VPN/proxy, ISP behavior, or target list.\n")
		}

		if jsonOut {
			out := Output{
				TS:      nowISO(),
				Status:  status,
				Verdict: verdict,
				Summary: groups,
				Results: results,
			}
			b, _ := json.Marshal(out)
			fmt.Println(string(b))
			return
		}

		fmt.Printf("[%s] status=%s verdict=%s\n", nowISO(), status, verdict)

		for _, r := range results {
			lat := "-"
			if r.LatencyMS > 0 {
				lat = fmt.Sprintf("%dms", r.LatencyMS)
			}

			ipInfo := ""
			if r.ChosenIP != "" {
				ipInfo = fmt.Sprintf(" ip=%s(%s)", r.ChosenIP, r.IPFamily)
			}

			httpPart := "HTTP" + icon(false)
			if r.HTTPOK {
				httpPart = fmt.Sprintf("%s%s:%d", r.HTTPMethod, icon(true), r.HTTPCode)
			}

			rowTag := ""
			if isFilteredGroup(r.Group) {
				rowTag = " (ignored)"
			}

			line := fmt.Sprintf(" - [%s] %-14s %-7s DNS%s TCP%s TLS%s %s%s %s%s",
				r.Group, r.Name, lat,
				icon(r.DNSOK),
				icon(r.TCP443OK),
				icon(r.TLSOK),
				httpPart,
				ipInfo,
				r.URL,
				rowTag,
			)

			if r.Err != "" {
				line += " err=" + r.Err
			}
			fmt.Println(line)
		}

		printGroupSummary(groups)

		if s, ok := groups["filtered"]; ok && s.Total > 0 && s.HTTP_OK > 0 {
			fmt.Printf("🚨🚨🚨 ALERT (repeat): filtered targets reachable (%d/%d) 🚨🚨🚨\n", s.HTTP_OK, s.Total)
		}
	}

	if loop {
		for {
			runOnce()
			time.Sleep(time.Duration(max(1, intervalSec)) * time.Second)
		}
	} else {
		runOnce()
	}
}

