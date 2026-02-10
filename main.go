package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string        `json:"listenAddr"`
	Routes     []RouteConfig `json:"routes"`
}

type RouteConfig struct {
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	AccessKeySecret string `json:"accessKeySecret"`
	InsecureTLS     *bool  `json:"insecureSkipVerify"`
}

type legacyConfig struct {
	ListenAddr      string `json:"listenAddr"`
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	AccessKeySecret string `json:"accessKeySecret"`
	InsecureTLS     *bool  `json:"insecureSkipVerify"`
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr: ":8080",
	}
	loadConfigFile(&cfg)

	if len(cfg.Routes) == 0 {
		log.Fatalf("missing required config in config.json: routes")
	}

	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		route.Bucket = strings.TrimSpace(route.Bucket)
		if route.Endpoint == "" {
			log.Fatalf("missing required config in config.json routes[%d]: endpoint", i)
		}
		if route.Bucket == "" {
			log.Fatalf("missing required config in config.json routes[%d]: bucket", i)
		}
		if route.AccessKeyID == "" {
			log.Fatalf("missing required config in config.json routes[%d]: accessKeyId", i)
		}
		if route.AccessKeySecret == "" {
			log.Fatalf("missing required config in config.json routes[%d]: accessKeySecret", i)
		}
		if route.Region == "" {
			route.Region = inferRegion(route.Endpoint)
		}
		if _, _, _, err := parseEndpoint(route.Endpoint); err != nil {
			log.Fatalf("invalid config routes[%d] endpoint=%q: %v", i, route.Endpoint, err)
		}
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
	if len(cfg.Routes) > 0 {
		return
	}

	var legacy legacyConfig
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return
	}
	if legacy.Endpoint == "" && legacy.Bucket == "" && legacy.AccessKeyID == "" && legacy.AccessKeySecret == "" {
		return
	}
	cfg.ListenAddr = legacy.ListenAddr
	cfg.Routes = []RouteConfig{{
		Endpoint:        legacy.Endpoint,
		Bucket:          legacy.Bucket,
		Region:          legacy.Region,
		AccessKeyID:     legacy.AccessKeyID,
		AccessKeySecret: legacy.AccessKeySecret,
		InsecureTLS:     legacy.InsecureTLS,
	}}
}

func inferRegion(endpoint string) string {
	host := extractEndpointHostname(endpoint)
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

	routesByBucket := make(map[string]*routeEntry, len(cfg.Routes))
	routesByAccessKeyID := make(map[string][]*routeEntry, len(cfg.Routes))
	var defaultRoute *routeEntry

	for _, routeCfg := range cfg.Routes {
		client, err := buildHTTPClient(routeCfg)
		if err != nil {
			log.Fatalf("failed to build upstream client for bucket=%s: %v", routeCfg.Bucket, err)
		}
		entry := &routeEntry{
			cfg:    routeCfg,
			client: client,
		}
		bucketKey := normalizeBucketKey(routeCfg.Bucket)
		if _, exists := routesByBucket[bucketKey]; exists {
			log.Fatalf("duplicated bucket in config routes: %q", routeCfg.Bucket)
		}
		routesByBucket[bucketKey] = entry
		accessKeyID := normalizeAccessKeyID(routeCfg.AccessKeyID)
		if accessKeyID != "" {
			routesByAccessKeyID[accessKeyID] = append(routesByAccessKeyID[accessKeyID], entry)
		}
		if len(cfg.Routes) == 1 {
			defaultRoute = entry
		}
	}

	h := &proxyHandler{
		routesByBucket:      routesByBucket,
		routesByAccessKeyID: routesByAccessKeyID,
		defaultRoute:        defaultRoute,
	}
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
	}

	buckets := make([]string, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		buckets = append(buckets, route.Bucket)
	}
	log.Printf("OSS proxy listening on %s, buckets=%s", cfg.ListenAddr, strings.Join(buckets, ","))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func buildHTTPClient(cfg RouteConfig) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	scheme, _, _, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(scheme, "https") {
		insecureTLS := cfg.insecureTLS()
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureTLS,
		}
		transport.TLSClientConfig = tlsConfig
	}

	return &http.Client{
		Timeout:   0,
		Transport: transport,
	}, nil
}

func (cfg RouteConfig) insecureTLS() bool {
	if cfg.InsecureTLS == nil {
		return true
	}
	return *cfg.InsecureTLS
}

type proxyHandler struct {
	routesByBucket      map[string]*routeEntry
	routesByAccessKeyID map[string][]*routeEntry
	defaultRoute        *routeEntry
}

type routeEntry struct {
	cfg    RouteConfig
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

	route, bucketName, err := h.resolveRoute(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	targetURL, err := h.buildTargetURL(r, route.cfg, bucketName)
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
	h.sanitizeAndSign(r, upReq, bodyBytes, route.cfg, bucketName)

	resp, err := route.client.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *proxyHandler) resolveRoute(r *http.Request) (*routeEntry, string, error) {
	if route, bucket := h.routeFromHost(r.Host); route != nil {
		return route, bucket, nil
	}
	if route, bucket := h.routeFromPath(r.URL.Path); route != nil {
		return route, bucket, nil
	}
	if route, bucket, err := h.routeFromAuthorization(r.Header.Get("Authorization")); route != nil || err != nil {
		return route, bucket, err
	}
	if h.defaultRoute != nil {
		return h.defaultRoute, h.defaultRoute.cfg.Bucket, nil
	}

	buckets := make([]string, 0, len(h.routesByBucket))
	for _, route := range h.routesByBucket {
		buckets = append(buckets, route.cfg.Bucket)
	}
	sort.Strings(buckets)
	return nil, "", fmt.Errorf("cannot determine bucket from request host/path, expected one of: %s", strings.Join(buckets, ","))
}

func (h *proxyHandler) routeFromAuthorization(authHeader string) (*routeEntry, string, error) {
	accessKeyID := parseAccessKeyIDFromAuthorization(authHeader)
	if accessKeyID == "" {
		return nil, "", nil
	}

	routes := h.routesByAccessKeyID[normalizeAccessKeyID(accessKeyID)]
	switch len(routes) {
	case 0:
		return nil, "", nil
	case 1:
		return routes[0], routes[0].cfg.Bucket, nil
	default:
		buckets := make([]string, 0, len(routes))
		for _, route := range routes {
			buckets = append(buckets, route.cfg.Bucket)
		}
		sort.Strings(buckets)
		return nil, "", fmt.Errorf("cannot determine bucket from Authorization accessKeyId=%s, expected one of: %s", accessKeyID, strings.Join(buckets, ","))
	}
}

func (h *proxyHandler) routeFromHost(hostport string) (*routeEntry, string) {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return nil, ""
	}
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]") {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
	} else if strings.Count(host, ":") == 1 {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			host = parsed
		}
	}
	host = normalizeBucketKey(host)
	if route, ok := h.routesByBucket[host]; ok {
		return route, route.cfg.Bucket
	}

	for key, route := range h.routesByBucket {
		if strings.HasPrefix(host, key+".") {
			return route, route.cfg.Bucket
		}
	}
	return nil, ""
}

func (h *proxyHandler) routeFromPath(path string) (*routeEntry, string) {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return nil, ""
	}
	first, _, _ := strings.Cut(trimmed, "/")
	if route, ok := h.routesByBucket[normalizeBucketKey(first)]; ok {
		return route, route.cfg.Bucket
	}
	return nil, ""
}

func normalizeBucketKey(bucket string) string {
	return strings.ToLower(strings.TrimSpace(bucket))
}

func normalizeAccessKeyID(accessKeyID string) string {
	return strings.TrimSpace(accessKeyID)
}

func parseAccessKeyIDFromAuthorization(auth string) string {
	raw := strings.TrimSpace(auth)
	if raw == "" {
		return ""
	}

	if strings.HasPrefix(raw, "OSS ") {
		cred := strings.TrimSpace(strings.TrimPrefix(raw, "OSS "))
		accessKeyID, _, ok := strings.Cut(cred, ":")
		if !ok {
			return ""
		}
		return strings.TrimSpace(accessKeyID)
	}

	if strings.HasPrefix(raw, "OSS4-HMAC-SHA256") {
		idx := strings.Index(raw, "Credential=")
		if idx < 0 {
			return ""
		}
		credentialPart := raw[idx+len("Credential="):]
		credentialPart, _, _ = strings.Cut(credentialPart, ",")
		credentialPart = strings.TrimSpace(credentialPart)
		accessKeyID, _, _ := strings.Cut(credentialPart, "/")
		return strings.TrimSpace(accessKeyID)
	}

	return ""
}

func (h *proxyHandler) buildTargetURL(r *http.Request, route RouteConfig, bucketName string) (*url.URL, error) {
	scheme, endpointHost, _, err := parseEndpoint(route.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %w", route.Endpoint, err)
	}

	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	path = normalizePath(path)
	path = stripLeadingBucket(path, bucketName)

	queryValues := stripAuthQueryParams(r.URL.Query())
	targetRawQuery := queryValues.Encode()

	host := endpointHost
	if strings.Contains(bucketName, ".") {
		// Buckets with dots can break TLS wildcard validation in virtual-host style.
		path = ensureBucketInPath(path, bucketName)
	} else {
		host = buildBucketHost(bucketName, route.Endpoint)
	}
	target := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: targetRawQuery,
	}
	return target, nil
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

func (h *proxyHandler) sanitizeAndSign(origReq, req *http.Request, body []byte, route RouteConfig, bucketName string) {
	removeHopByHopHeaders(req.Header)

	req.Host = req.URL.Host
	req.Header.Set("Host", req.URL.Host)
	req.Header.Del("Authorization")
	req.Header.Del("Date")

	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	} else {
		req.ContentLength = 0
	}

	if shouldSignV4(origReq) {
		h.signAsV4(req, route, bucketName)
		return
	}

	req.Header.Del("X-Oss-Date")
	req.Header.Del("X-Oss-Signature-Version")
	req.Header.Del("X-Oss-Content-Sha256")
	req.Header.Del("X-Oss-Additional-Headers")

	now := time.Now().UTC()
	date := now.Format(http.TimeFormat)
	req.Header.Set("Date", date)

	auth := signV1(req, route.AccessKeyID, route.AccessKeySecret, bucketName)
	req.Header.Set("Authorization", auth)
}

func shouldSignV4(origReq *http.Request) bool {
	auth := strings.TrimSpace(origReq.Header.Get("Authorization"))
	if strings.HasPrefix(auth, "OSS4-HMAC-SHA256") {
		return true
	}
	if strings.HasPrefix(auth, "OSS ") {
		return false
	}

	if looksLikeV4SignatureVersion(origReq.Header.Get("X-Oss-Signature-Version")) {
		return true
	}
	if looksLikeV4SignatureVersion(origReq.URL.Query().Get("x-oss-signature-version")) {
		return true
	}
	if origReq.URL.Query().Get("x-oss-credential") != "" || origReq.URL.Query().Get("x-oss-signature") != "" {
		return true
	}
	if origReq.URL.Query().Get("OSSAccessKeyId") != "" || origReq.URL.Query().Get("Signature") != "" || origReq.URL.Query().Get("Expires") != "" {
		return false
	}

	// For unsigned browser/direct-link requests, prefer V1 for broader OSS compatibility.
	return false
}

func looksLikeV4SignatureVersion(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	return v == "v4" || v == "oss4-hmac-sha256"
}

func (h *proxyHandler) signAsV4(req *http.Request, route RouteConfig, bucketName string) {
	now := time.Now().UTC()
	signDate := now.Format("20060102")
	ossDate := now.Format("20060102T150405Z")
	region := route.Region
	if region == "" {
		region = inferRegion(route.Endpoint)
	}

	req.Header.Del("Date")
	req.Header.Del("X-Oss-Signature-Version")
	req.Header.Del("X-Oss-Additional-Headers")
	req.Header.Set("X-Oss-Date", ossDate)
	req.Header.Set("X-Oss-Content-Sha256", "UNSIGNED-PAYLOAD")

	canonicalHeaders := buildCanonicalV4Headers(req.Header)
	canonicalRequest := strings.Join([]string{
		req.Method,
		buildCanonicalURI(req.URL, bucketName),
		buildCanonicalQuery(req.URL.Query()),
		canonicalHeaders,
		"",
		"UNSIGNED-PAYLOAD",
	}, "\n")

	stringToSign := strings.Join([]string{
		"OSS4-HMAC-SHA256",
		ossDate,
		signDate + "/" + region + "/oss/aliyun_v4_request",
		sha256Hex(canonicalRequest),
	}, "\n")

	signingKey := deriveV4SigningKey(route.AccessKeySecret, signDate, region)
	sig := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	auth := fmt.Sprintf(
		"OSS4-HMAC-SHA256 Credential=%s/%s/%s/oss/aliyun_v4_request,Signature=%s",
		route.AccessKeyID, signDate, region, sig,
	)
	if os.Getenv("OSS_PROXY_DEBUG_SIGN") == "1" {
		log.Printf("v4 canonicalRequest:\n%s\nv4 stringToSign:\n%s\nv4 signature=%s", canonicalRequest, stringToSign, sig)
	}
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
	if os.Getenv("OSS_PROXY_DEBUG_SIGN") == "1" {
		log.Printf("v1 stringToSign:\n%s\nv1 signature=%s", stringToSign, sig)
	}
	return "OSS " + ak + ":" + sig
}

func buildCanonicalV4Headers(h http.Header) string {
	keys := make([]string, 0, len(h))
	seen := make(map[string]struct{}, len(h))
	for k := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" {
			continue
		}
		if lk == "content-type" || lk == "content-md5" || strings.HasPrefix(lk, "x-oss-") {
			if _, ok := seen[lk]; ok {
				continue
			}
			seen[lk] = struct{}{}
			keys = append(keys, lk)
		}
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		vals := h.Values(http.CanonicalHeaderKey(k))
		cleanVals := make([]string, 0, len(vals))
		for _, v := range vals {
			cleanVals = append(cleanVals, strings.TrimSpace(v))
		}
		b.WriteString(k)
		b.WriteString(":")
		b.WriteString(strings.Join(cleanVals, ","))
		b.WriteString("\n")
	}
	return b.String()
}

func buildCanonicalURI(u *url.URL, bucketName string) string {
	escaped := u.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	if bucketName != "" {
		trimmed := strings.TrimPrefix(escaped, "/")
		if trimmed != bucketName && !strings.HasPrefix(trimmed, bucketName+"/") {
			escaped = "/" + bucketName + escaped
		}
	}
	return escaped
}

func buildCanonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	type pair struct {
		k string
		v string
	}
	pairs := make([]pair, 0)
	for k, vals := range values {
		if len(vals) == 0 {
			pairs = append(pairs, pair{k: encodeRFC3986(k), v: ""})
			continue
		}
		for _, v := range vals {
			pairs = append(pairs, pair{k: encodeRFC3986(k), v: encodeRFC3986(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k == pairs[j].k {
			return pairs[i].v < pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if p.v == "" {
			parts = append(parts, p.k)
			continue
		}
		parts = append(parts, p.k+"="+p.v)
	}
	return strings.Join(parts, "&")
}

func encodeRFC3986(raw string) string {
	escaped := url.QueryEscape(raw)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, raw string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(raw))
	return mac.Sum(nil)
}

func deriveV4SigningKey(sk, signDate, region string) []byte {
	kDate := hmacSHA256([]byte("aliyun_v4"+sk), signDate)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, "oss")
	return hmacSHA256(kService, "aliyun_v4_request")
}

func buildCanonicalOSSHeaders(h http.Header) string {
	keys := make([]string, 0)
	valuesByKey := make(map[string]string)
	for k, vals := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		if !strings.HasPrefix(lk, "x-oss-") {
			continue
		}
		cleanVals := make([]string, 0, len(vals))
		for _, v := range vals {
			cleanVals = append(cleanVals, strings.TrimSpace(v))
		}
		keys = append(keys, lk)
		valuesByKey[lk] = strings.Join(cleanVals, ",")
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+":"+valuesByKey[k])
	}
	return strings.Join(lines, "\n") + "\n"
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
	"x-oss-rename": {},
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
	hostName, port := extractEndpointHostPort(endpoint)
	if hostName == "" {
		return bucketName + "." + endpoint
	}
	host := bucketName + "." + hostName
	if port != "" {
		host += ":" + port
	}
	return host
}

func extractEndpointHostname(endpoint string) string {
	host, _ := extractEndpointHostPort(endpoint)
	if host == "" {
		return endpoint
	}
	return host
}

func extractEndpointHostPort(endpoint string) (string, string) {
	_, host, port, err := parseEndpoint(endpoint)
	if err != nil {
		return "", ""
	}
	return host, port
}

func parseEndpoint(endpoint string) (string, string, string, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return "", "", "", fmt.Errorf("empty endpoint")
	}

	parseAsURL := strings.Contains(raw, "://")
	if !parseAsURL {
		// Backward compatible: endpoint without scheme defaults to https.
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", "", err
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return "", "", "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return "", "", "", fmt.Errorf("missing host")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", "", "", fmt.Errorf("endpoint should not contain path")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", "", fmt.Errorf("endpoint should not contain query or fragment")
	}
	return scheme, parsed.Hostname(), parsed.Port(), nil
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
