package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	ListenAddr       string `json:"listenAddr"`
	Endpoint         string `json:"endpoint"`
	Region           string `json:"region"`
	AccessKeyID      string `json:"accessKeyId"`
	AccessKeySecret  string `json:"accessKeySecret"`
	SecurityToken    string `json:"securityToken"`
	ForceBucket      string `json:"forceBucket"`
	InsecureUpstream bool   `json:"insecureUpstream"`
	SignatureVersion string `json:"signatureVersion"`
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr:       ":8080",
		SignatureVersion: "auto",
	}
	loadConfigFile(&cfg)

	overrideFromEnv(&cfg)

	if cfg.Endpoint == "" {
		log.Fatalf("missing required config: OSS_ENDPOINT")
	}
	if cfg.AccessKeyID == "" {
		log.Fatalf("missing required config: OSS_ACCESS_KEY_ID")
	}
	if cfg.AccessKeySecret == "" {
		log.Fatalf("missing required config: OSS_ACCESS_KEY_SECRET")
	}
	if cfg.Region == "" {
		cfg.Region = inferRegion(cfg.Endpoint)
	}
	return cfg
}

func getEnv(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func loadConfigFile(cfg *Config) {
	path := strings.TrimSpace(os.Getenv("OSS_CONFIG"))
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read OSS_CONFIG: %v", err)
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		log.Fatalf("failed to parse OSS_CONFIG: %v", err)
	}
}

func overrideFromEnv(cfg *Config) {
	if v := strings.TrimSpace(os.Getenv("LISTEN_ADDR")); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("OSS_ENDPOINT")); v != "" {
		cfg.Endpoint = v
	}
	if v := strings.TrimSpace(os.Getenv("OSS_REGION")); v != "" {
		cfg.Region = v
	}
	if v := strings.TrimSpace(os.Getenv("OSS_ACCESS_KEY_ID")); v != "" {
		cfg.AccessKeyID = v
	}
	if v := strings.TrimSpace(os.Getenv("OSS_ACCESS_KEY_SECRET")); v != "" {
		cfg.AccessKeySecret = v
	}
	if v := strings.TrimSpace(os.Getenv("OSS_SECURITY_TOKEN")); v != "" {
		cfg.SecurityToken = v
	}
	if v := strings.TrimSpace(os.Getenv("OSS_FORCE_BUCKET")); v != "" {
		cfg.ForceBucket = v
	}
	if v := strings.TrimSpace(os.Getenv("OSS_INSECURE_UPSTREAM")); v != "" {
		cfg.InsecureUpstream = strings.EqualFold(v, "true")
	}
	if v := strings.TrimSpace(os.Getenv("OSS_SIGNATURE_VERSION")); v != "" {
		cfg.SignatureVersion = strings.ToLower(v)
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

	targetURL, err := h.buildTargetURL(r)
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
	h.sanitizeAndSign(upReq, bodyBytes)

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

func (h *proxyHandler) buildTargetURL(r *http.Request) (*url.URL, error) {
	scheme := "https"
	if h.cfg.InsecureUpstream {
		scheme = "http"
	}

	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if h.cfg.ForceBucket != "" {
		trimmed := strings.TrimPrefix(path, "/")
		path = "/" + h.cfg.ForceBucket
		if trimmed != "" {
			path += "/" + trimmed
		}
	}

	targetRawQuery := r.URL.RawQuery
	target := &url.URL{
		Scheme:   scheme,
		Host:     h.cfg.Endpoint,
		Path:     path,
		RawPath:  path,
		RawQuery: targetRawQuery,
	}
	return target, nil
}

func (h *proxyHandler) sanitizeAndSign(req *http.Request, body []byte) {
	removeHopByHopHeaders(req.Header)

	useV4 := h.useV4(req.Header)

	req.Host = h.cfg.Endpoint
	req.Header.Set("Host", h.cfg.Endpoint)
	req.Header.Del("Authorization")
	req.Header.Del("Date")
	req.Header.Del("X-Oss-Date")

	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	} else {
		req.ContentLength = 0
	}

	if h.cfg.SecurityToken != "" {
		req.Header.Set("x-oss-security-token", h.cfg.SecurityToken)
	}

	if useV4 {
		h.signV4(req, body)
		return
	}

	now := time.Now().UTC()
	date := now.Format(http.TimeFormat)
	req.Header.Set("Date", date)

	auth := signV1(req, h.cfg.AccessKeyID, h.cfg.AccessKeySecret)
	req.Header.Set("Authorization", auth)
}

func shouldUseV4(h http.Header) bool {
	if strings.EqualFold(strings.TrimSpace(h.Get("x-oss-signature-version")), "OSS4-HMAC-SHA256") {
		return true
	}
	auth := strings.TrimSpace(h.Get("Authorization"))
	return strings.HasPrefix(auth, "OSS4-HMAC-SHA256")
}

func (h *proxyHandler) useV4(headers http.Header) bool {
	switch h.cfg.SignatureVersion {
	case "v1":
		return false
	case "v4":
		return true
	default:
		return shouldUseV4(headers)
	}
}

func signV1(req *http.Request, ak, sk string) string {
	md5 := req.Header.Get("Content-MD5")
	contentType := req.Header.Get("Content-Type")
	date := req.Header.Get("Date")

	canonicalHeaders := buildCanonicalOSSHeaders(req.Header)
	canonicalResource := buildCanonicalResource(req.URL)

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

func (h *proxyHandler) signV4(req *http.Request, body []byte) {
	amzDate := time.Now().UTC().Format("20060102T150405Z")
	req.Header.Set("x-oss-date", amzDate)
	req.Header.Set("x-oss-signature-version", "OSS4-HMAC-SHA256")
	if h.cfg.SecurityToken != "" {
		req.Header.Set("x-oss-security-token", h.cfg.SecurityToken)
	}

	payloadHash := sha256Hex(body)
	req.Header.Set("x-oss-content-sha256", payloadHash)

	canonicalHeaders, signedHeaders := canonicalHeadersV4(req.Header)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/oss/aliyun_v4_request", amzDate[:8], h.cfg.Region)
	stringToSign := strings.Join([]string{
		"OSS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := v4SigningKey(h.cfg.AccessKeySecret, amzDate[:8], h.cfg.Region)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	authorization := fmt.Sprintf(
		"OSS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		h.cfg.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authorization)
}

func canonicalHeadersV4(h http.Header) (string, string) {
	type header struct {
		key   string
		value string
	}
	headers := make([]header, 0)
	for k, vals := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "authorization" || lk == "host" {
			continue
		}
		cleanVals := make([]string, 0, len(vals))
		for _, v := range vals {
			cleanVals = append(cleanVals, strings.TrimSpace(v))
		}
		headers = append(headers, header{key: lk, value: strings.Join(cleanVals, ",")})
	}
	host := h.Get("Host")
	if host == "" {
		host = h.Get("host")
	}
	if host != "" {
		headers = append(headers, header{key: "host", value: host})
	}
	if len(headers) == 0 {
		return "", ""
	}
	sort.Slice(headers, func(i, j int) bool {
		return headers[i].key < headers[j].key
	})

	var canonical strings.Builder
	signed := make([]string, 0, len(headers))
	for _, hv := range headers {
		canonical.WriteString(hv.key)
		canonical.WriteString(":")
		canonical.WriteString(hv.value)
		canonical.WriteString("\n")
		signed = append(signed, hv.key)
	}
	return canonical.String(), strings.Join(signed, ";")
}

func canonicalURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func canonicalQuery(u *url.URL) string {
	values := u.Query()
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := values[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, encodeQueryComponent(k)+"="+encodeQueryComponent(v))
		}
	}
	return strings.Join(parts, "&")
}

func encodeQueryComponent(value string) string {
	escaped := url.QueryEscape(value)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func v4SigningKey(secret, date, region string) []byte {
	kDate := hmacSHA256([]byte("aliyun_v4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "oss")
	kSigning := hmacSHA256(kService, "aliyun_v4_request")
	return kSigning
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
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
	"security-token": {}, "position": {}, "symlink": {}, "restore": {}, "replication": {}, "replicationlocation": {},
	"replicationprogress": {}, "transferacceleration": {}, "cname": {}, "live": {}, "status": {}, "comp": {}, "vod": {},
	"starttime": {}, "endtime": {}, "inventory": {}, "inventoryid": {}, "continuation-token": {}, "asyncfetch": {},
	"callback": {}, "callback-var": {}, "sequential": {}, "worm": {}, "wormid": {}, "wormextend": {}, "qos": {}, "stat": {},
	"response-content-type": {}, "response-content-language": {}, "response-expires": {}, "response-cache-control": {},
	"response-content-disposition": {}, "response-content-encoding": {}, "x-oss-process": {},
}

func buildCanonicalResource(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
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
