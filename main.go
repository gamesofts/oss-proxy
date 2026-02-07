package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type Config struct {
	ListenAddr      string `json:"listenAddr"`
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	AccessKeySecret string `json:"accessKeySecret"`
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr: ":8080",
	}
	loadConfigFile(&cfg)

	if cfg.Endpoint == "" {
		log.Fatalf("missing required config in config.json: endpoint")
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		log.Fatalf("missing required config in config.json: bucket")
	}
	if cfg.AccessKeyID == "" {
		log.Fatalf("missing required config in config.json: accessKeyId")
	}
	if cfg.AccessKeySecret == "" {
		log.Fatalf("missing required config in config.json: accessKeySecret")
	}
	if cfg.Region == "" {
		cfg.Region = inferRegion(cfg.Endpoint)
	}
	return cfg
}

func loadConfigFile(cfg *Config) {
	path := "config.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		log.Fatalf("failed to parse %s: %v", path, err)
	}
}

func inferRegion(endpoint string) string {
	host := strings.Split(endpoint, ":")[0]
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if strings.HasPrefix(label, "oss-") {
			trimmed := strings.TrimPrefix(label, "oss-")
			parts := strings.SplitN(trimmed, ".", 2)
			return parts[0]
		}
	}
	return ""
}

func main() {
	cfg := loadConfig()

	h := &proxyHandler{cfg: cfg, client: &http.Client{Timeout: 0}}
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
	}

	log.Printf("OSS proxy listening on %s, endpoint=%s", cfg.ListenAddr, cfg.Endpoint)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

type proxyHandler struct {
	cfg    Config
	client *http.Client
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	targetURL, bucketName, err := h.buildTargetURL(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	upReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}

	cloneHeaders(r.Header, upReq.Header)
	h.sanitizeAndSign(upReq, bodyBytes, bucketName)

	resp, err := h.client.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *proxyHandler) buildTargetURL(r *http.Request) (*url.URL, string, error) {
	scheme := "https"
	bucketName := strings.TrimSpace(h.cfg.Bucket)

	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	path = normalizePath(path)
	path = stripLeadingBucket(path, bucketName)

	queryValues := stripAuthQueryParams(r.URL.Query())
	targetRawQuery := queryValues.Encode()

	host := h.cfg.Endpoint
	if strings.Contains(bucketName, ".") {
		// Buckets with dots can break TLS wildcard validation in virtual-host style.
		path = ensureBucketInPath(path, bucketName)
	} else {
		host = buildBucketHost(bucketName, h.cfg.Endpoint)
	}
	target := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: targetRawQuery,
	}
	return target, bucketName, nil
}

func normalizePath(path string) string {
	normalized := path
	for i := 0; i < 2; i++ {
		unescaped, err := url.PathUnescape(normalized)
		if err != nil || unescaped == normalized {
			break
		}
		normalized = unescaped
	}
	if normalized == "" {
		return "/"
	}
	return normalized
}

func stripAuthQueryParams(values url.Values) url.Values {
	if len(values) == 0 {
		return values
	}
	filtered := make(url.Values, len(values))
	for k, v := range values {
		if isAuthQueryParam(k) {
			continue
		}
		filtered[k] = append([]string(nil), v...)
	}
	return filtered
}

func isAuthQueryParam(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "ossaccesskeyid", "signature", "expires",
		"x-oss-signature-version", "x-oss-credential", "x-oss-date", "x-oss-expires", "x-oss-signature", "x-oss-additional-headers",
		"security-token", "x-oss-security-token":
		return true
	default:
		return false
	}
}

func ensureBucketInPath(path, bucket string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "/" + bucket
	}
	if trimmed == bucket || strings.HasPrefix(trimmed, bucket+"/") {
		return "/" + trimmed
	}
	return "/" + bucket + "/" + trimmed
}

func stripLeadingBucket(path, bucket string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "/"
	}
	if trimmed == bucket {
		return "/"
	}
	prefix := bucket + "/"
	if strings.HasPrefix(trimmed, prefix) {
		trimmed = strings.TrimPrefix(trimmed, prefix)
	}
	if trimmed == "" {
		return "/"
	}
	return "/" + trimmed
}

func (h *proxyHandler) sanitizeAndSign(req *http.Request, body []byte, bucketName string) {
	removeHopByHopHeaders(req.Header)

	req.Host = req.URL.Host
	req.Header.Set("Host", req.URL.Host)
	req.Header.Del("Authorization")
	req.Header.Del("Date")
	req.Header.Del("X-Oss-Date")
	// Force V1 signing semantics even when clients send V4-specific headers.
	req.Header.Del("X-Oss-Signature-Version")
	req.Header.Del("X-Oss-Content-Sha256")
	req.Header.Del("X-Oss-Additional-Headers")

	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	} else {
		req.ContentLength = 0
	}

	now := time.Now().UTC()
	date := now.Format(http.TimeFormat)
	req.Header.Set("Date", date)

	auth := signV1(req, h.cfg.AccessKeyID, h.cfg.AccessKeySecret, bucketName)
	req.Header.Set("Authorization", auth)
}

func signV1(req *http.Request, ak, sk string, bucketName string) string {
	md5 := req.Header.Get("Content-MD5")
	contentType := req.Header.Get("Content-Type")
	date := req.Header.Get("Date")

	canonicalHeaders := buildCanonicalOSSHeaders(req.Header)
	canonicalResource := buildCanonicalResource(req.URL, bucketName)

	stringToSign := strings.Join([]string{
		req.Method,
		md5,
		contentType,
		date,
		canonicalHeaders + canonicalResource,
	}, "\n")

	mac := hmac.New(sha1.New, []byte(sk))
	_, _ = mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return "OSS " + ak + ":" + sig
}

func buildCanonicalOSSHeaders(h http.Header) string {
	pairs := make([]string, 0)
	for k, vals := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if !strings.HasPrefix(lk, "x-oss-") {
			continue
		}
		cleanVals := make([]string, 0, len(vals))
		for _, v := range vals {
			cleanVals = append(cleanVals, strings.TrimSpace(v))
		}
		pairs = append(pairs, lk+":"+strings.Join(cleanVals, ","))
	}
	sort.Strings(pairs)
	if len(pairs) == 0 {
		return ""
	}
	return strings.Join(pairs, "\n") + "\n"
}

var subresourceAllowlist = map[string]struct{}{
	"acl": {}, "uploads": {}, "location": {}, "cors": {}, "logging": {}, "website": {}, "referer": {},
	"lifecycle": {}, "delete": {}, "append": {}, "tagging": {}, "objectmeta": {}, "uploadid": {}, "partnumber": {},
	"bucketinfo":     {},
	"security-token": {}, "position": {}, "symlink": {}, "restore": {}, "replication": {}, "replicationlocation": {},
	"replicationprogress": {}, "transferacceleration": {}, "cname": {}, "live": {}, "status": {}, "comp": {}, "vod": {},
	"starttime": {}, "endtime": {}, "inventory": {}, "inventoryid": {}, "continuation-token": {}, "asyncfetch": {},
	"callback": {}, "callback-var": {}, "sequential": {}, "worm": {}, "wormid": {}, "wormextend": {}, "qos": {}, "stat": {},
	"response-content-type": {}, "response-content-language": {}, "response-expires": {}, "response-cache-control": {},
	"response-content-disposition": {}, "response-content-encoding": {}, "x-oss-process": {},
}

func buildCanonicalResource(u *url.URL, bucketName string) string {
	path := u.Path
	if path == "" {
		path = "/"
	}
	if bucketName != "" {
		trimmed := strings.TrimPrefix(path, "/")
		if trimmed != bucketName && !strings.HasPrefix(trimmed, bucketName+"/") {
			path = "/" + bucketName + path
		}
	}

	values := u.Query()
	keys := make([]string, 0)
	for k := range values {
		lk := strings.ToLower(k)
		if _, ok := subresourceAllowlist[lk]; ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return path
	}

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := values[k]
		if len(vals) == 0 || vals[0] == "" {
			parts = append(parts, k)
			continue
		}
		sortedVals := append([]string(nil), vals...)
		sort.Strings(sortedVals)
		parts = append(parts, k+"="+sortedVals[0])
	}
	return path + "?" + strings.Join(parts, "&")
}

func buildBucketHost(bucketName, endpoint string) string {
	parsed, err := url.Parse("//" + endpoint)
	if err != nil || parsed.Hostname() == "" {
		return bucketName + "." + endpoint
	}
	host := bucketName + "." + parsed.Hostname()
	if parsed.Port() != "" {
		host += ":" + parsed.Port()
	}
	return host
}

func removeHopByHopHeaders(h http.Header) {
	hopByHop := []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
	}
	for _, k := range hopByHop {
		h.Del(k)
	}
}

func cloneHeaders(src, dst http.Header) {
	for k, vals := range src {
		copied := append([]string(nil), vals...)
		dst[k] = copied
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}
