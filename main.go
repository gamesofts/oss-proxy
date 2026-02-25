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
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	ListenAddr string        `json:"listenAddr"`
	LogMode    string        `json:"logMode"`
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
	LogMode         string `json:"logMode"`
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	AccessKeySecret string `json:"accessKeySecret"`
	InsecureTLS     *bool  `json:"insecureSkipVerify"`
}

type logMode string

const (
	logModeDebug logMode = "debug"
	logModeInfo  logMode = "info"
	logModeError logMode = "error"
	logModeNone  logMode = "none"
)

const (
	defaultErrorBodyPeekBytes       = 64 * 1024
	defaultCopyBufferSize           = 256 * 1024
	defaultServerIdleTimeout        = 120 * time.Second
	defaultServerMaxHeaderBytes     = 1 << 20
	defaultDialTimeout              = 5 * time.Second
	defaultDialKeepAlive            = 30 * time.Second
	defaultIdleConnTimeout          = 90 * time.Second
	defaultTLSHandshakeTimeout      = 10 * time.Second
	defaultExpectContinueTimeout    = 1 * time.Second
	defaultResponseHeaderTimeout    = 30 * time.Second
	defaultTransportReadBufferSize  = 64 * 1024
	defaultTransportWriteBufferSize = 64 * 1024
	defaultMaxIdleConns             = 2048
	defaultMaxIdleConnsPerHost      = 512
)

func normalizeLogMode(raw string) logMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(logModeDebug):
		return logModeDebug
	case "", string(logModeInfo):
		return logModeInfo
	case string(logModeError):
		return logModeError
	case string(logModeNone):
		return logModeNone
	default:
		return logModeInfo
	}
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr: ":8080",
	}
	loadConfigFile(&cfg)
	cfg.LogMode = string(normalizeLogMode(cfg.LogMode))

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
	cfg.LogMode = legacy.LogMode
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
	transportsByKey := make(map[string]http.RoundTripper)
	var defaultRoute *routeEntry

	for _, routeCfg := range cfg.Routes {
		client, err := buildHTTPClient(routeCfg, transportsByKey)
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
		logMode:             normalizeLogMode(cfg.LogMode),
		copyBufPool: sync.Pool{
			New: func() any {
				buf := make([]byte, defaultCopyBufferSize)
				return &buf
			},
		},
	}
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       defaultServerIdleTimeout,
		MaxHeaderBytes:    defaultServerMaxHeaderBytes,
	}

	buckets := make([]string, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		buckets = append(buckets, route.Bucket)
	}
	h.logInfof("OSS proxy listening on %s, buckets=%s, log_mode=%s", cfg.ListenAddr, strings.Join(buckets, ","), h.logMode)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func buildHTTPClient(cfg RouteConfig, shared map[string]http.RoundTripper) (*http.Client, error) {
	scheme, _, _, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	cacheKey := strings.ToLower(strings.TrimSpace(cfg.Endpoint)) + "|" + fmt.Sprintf("insecure=%t", cfg.insecureTLS())
	transport, ok := shared[cacheKey]
	if !ok {
		transport, err = buildTransport(cfg, scheme)
		if err != nil {
			return nil, err
		}
		shared[cacheKey] = transport
	}
	return &http.Client{
		Timeout:   0,
		Transport: transport,
	}, nil
}

func buildTransport(cfg RouteConfig, scheme string) (http.RoundTripper, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = defaultMaxIdleConns
	transport.MaxIdleConnsPerHost = defaultMaxIdleConnsPerHost
	transport.MaxConnsPerHost = 0
	transport.IdleConnTimeout = defaultIdleConnTimeout
	transport.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	transport.ExpectContinueTimeout = defaultExpectContinueTimeout
	transport.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	transport.ReadBufferSize = defaultTransportReadBufferSize
	transport.WriteBufferSize = defaultTransportWriteBufferSize
	transport.ForceAttemptHTTP2 = true
	transport.DialContext = (&net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: defaultDialKeepAlive,
	}).DialContext
	if strings.EqualFold(scheme, "https") {
		insecureTLS := cfg.insecureTLS()
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureTLS,
		}
		transport.TLSClientConfig = tlsConfig
	}
	return transport, nil
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
	logMode             logMode
	copyBufPool         sync.Pool
}

type routeEntry struct {
	cfg    RouteConfig
	client *http.Client

	v4SigningKeyMu   sync.RWMutex
	v4SigningKeyDate string
	v4SigningRegion  string
	v4SigningKey     []byte
}

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()
	isObjectMetaReq := isObjectMetaRequest(r)
	h.logRequestDebug("incoming request", r)
	route, bucketName, err := h.resolveRoute(r)
	if err != nil {
		h.logRequestError("route resolve failed", err, r)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	targetURL, err := h.buildTargetURL(r, route.cfg, bucketName)
	if err != nil {
		h.logRequestError("build target url failed", err, r)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	upstreamMethod := r.Method
	var upstreamBody io.Reader = r.Body
	if isObjectMetaReq && r.Method == http.MethodGet {
		upstreamMethod = http.MethodHead
		upstreamBody = nil
	}
	upReq, err := http.NewRequestWithContext(ctx, upstreamMethod, targetURL.String(), upstreamBody)
	if err != nil {
		h.logRequestError("build upstream request failed", err, r)
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}
	upReq.ContentLength = r.ContentLength
	if isObjectMetaReq && upstreamMethod == http.MethodHead {
		upReq.ContentLength = 0
	}

	cloneHeaders(r.Header, upReq.Header)
	if isObjectMetaReq && upstreamMethod == http.MethodHead {
		upReq.Header.Del("Content-Length")
	}
	h.sanitizeAndSign(r, upReq, route, bucketName)

	resp, err := route.client.Do(upReq)
	if err != nil {
		h.logRequestError("upstream request failed", err, r)
		http.Error(w, fmt.Sprintf("upstream request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w.Header(), resp.Header)
	if isObjectMetaReq && r.Method != http.MethodHead {
		normalizeObjectMetaGETResponseHeaders(w.Header())
	}
	w.WriteHeader(resp.StatusCode)
	if isObjectMetaReq {
		// GetObjectMeta returns metadata headers only. Its Content-Length is object size metadata,
		// not a response body length we should read, otherwise the proxy can block and hit EOF later.
		h.logRequestSummary(r, resp.StatusCode, 0, start, targetURL)
		return
	}
	if resp.StatusCode < http.StatusBadRequest {
		n, copyErr := h.copyResponseBody(w, resp.Body)
		if copyErr != nil {
			h.logRequestError("copy upstream response body failed", copyErr, r)
		}
		h.logRequestSummary(r, resp.StatusCode, n, start, targetURL)
		return
	}

	switch h.logMode {
	case logModeNone:
		n, err := h.copyResponseBody(w, resp.Body)
		if err != nil {
			h.logRequestError("copy upstream error response body failed", err, r)
		}
		h.logRequestSummary(r, resp.StatusCode, n, start, targetURL)
	default:
		capture := newLimitedCaptureWriter(defaultErrorBodyPeekBytes)
		tee := io.TeeReader(resp.Body, capture)
		n, err := h.copyResponseBody(w, tee)
		if err != nil {
			h.logRequestError("copy upstream error response body failed", err, r)
		}
		h.logUpstreamHTTPErrorSample(resp, capture.Bytes(), capture.Truncated(), r, targetURL)
		h.logRequestSummary(r, resp.StatusCode, n, start, targetURL)
		return
	}
}

func (h *proxyHandler) logEnabledDebug() bool {
	return h != nil && h.logMode == logModeDebug
}

func (h *proxyHandler) logEnabledInfo() bool {
	if h == nil {
		return true
	}
	return h.logMode == logModeDebug || h.logMode == logModeInfo
}

func (h *proxyHandler) logEnabledError() bool {
	if h == nil {
		return true
	}
	return h.logMode != logModeNone
}

func (h *proxyHandler) logDebugf(format string, args ...any) {
	if h.logEnabledDebug() {
		log.Printf("[DEBUG] "+format, args...)
	}
}

func (h *proxyHandler) logInfof(format string, args ...any) {
	if h.logEnabledInfo() {
		log.Printf("[INFO] "+format, args...)
	}
}

func (h *proxyHandler) logErrorf(format string, args ...any) {
	if h.logEnabledError() {
		log.Printf("[ERROR] "+format, args...)
	}
}

func (h *proxyHandler) logRequestDebug(prefix string, r *http.Request) {
	if !h.logEnabledDebug() || r == nil {
		return
	}
	requestURI := r.RequestURI
	path := ""
	rawQuery := ""
	rawURL := ""
	if r.URL != nil {
		path = r.URL.Path
		rawQuery = r.URL.RawQuery
		rawURL = r.URL.String()
	}
	h.logDebugf(
		"%s: method=%s host=%q request_uri=%q path=%q raw_query=%q remote_addr=%q proto=%q url=%q content_length=%d headers=%v",
		prefix,
		r.Method,
		r.Host,
		requestURI,
		path,
		rawQuery,
		r.RemoteAddr,
		r.Proto,
		rawURL,
		r.ContentLength,
		r.Header,
	)
}

func (h *proxyHandler) logRequestSummary(r *http.Request, status int, bytesCopied int64, startedAt time.Time, targetURL *url.URL) {
	if !h.logEnabledInfo() || r == nil {
		return
	}
	target := ""
	if targetURL != nil {
		target = targetURL.String()
	}
	h.logInfof(
		"request summary: method=%s host=%q request_uri=%q status=%d bytes=%d duration=%s remote_addr=%q target_url=%q",
		r.Method,
		r.Host,
		r.RequestURI,
		status,
		bytesCopied,
		time.Since(startedAt).Round(time.Millisecond),
		r.RemoteAddr,
		target,
	)
}

func (h *proxyHandler) logRequestError(prefix string, err error, r *http.Request) {
	if !h.logEnabledError() {
		return
	}
	if r == nil {
		h.logErrorf("%s: %v", prefix, err)
		return
	}
	if h.logEnabledDebug() {
		h.logRequestDebug(prefix, r)
		h.logErrorf("%s: %v", prefix, err)
		return
	}
	h.logErrorf("%s: %v: method=%s host=%q request_uri=%q remote_addr=%q", prefix, err, r.Method, r.Host, r.RequestURI, r.RemoteAddr)
}

func (h *proxyHandler) logUpstreamHTTPErrorSample(resp *http.Response, sample []byte, truncated bool, req *http.Request, targetURL *url.URL) {
	if !h.logEnabledError() || resp == nil {
		return
	}
	snippet := "<omitted>"
	if h.logEnabledInfo() {
		snippet = "<empty>"
		if len(sample) > 0 {
			snippet = strings.TrimSpace(string(sample))
			if snippet == "" {
				snippet = "<empty>"
			}
		}
	}
	parsedErr := parseOSSErrorBody(sample)
	target := ""
	if targetURL != nil {
		target = targetURL.String()
	}
	h.logErrorf(
		"upstream returned error: status=%d status_text=%q content_type=%q x_oss_request_id=%q x_oss_ec=%q parsed_code=%q parsed_message=%q parsed_request_id=%q parsed_host_id=%q parsed_ec=%q truncated=%t target_url=%q method=%s host=%q request_uri=%q remote_addr=%q body=%q",
		resp.StatusCode,
		resp.Status,
		resp.Header.Get("Content-Type"),
		resp.Header.Get("x-oss-request-id"),
		resp.Header.Get("x-oss-ec"),
		parsedErr.Code,
		parsedErr.Message,
		parsedErr.RequestID,
		parsedErr.HostID,
		parsedErr.EC,
		truncated,
		target,
		req.Method,
		req.Host,
		req.RequestURI,
		req.RemoteAddr,
		snippet,
	)
}

func (h *proxyHandler) copyResponseBody(w io.Writer, body io.Reader) (int64, error) {
	if body == nil {
		return 0, nil
	}
	bufPtr := h.copyBufPool.Get().(*[]byte)
	defer h.copyBufPool.Put(bufPtr)
	return io.CopyBuffer(w, body, *bufPtr)
}

func (h *proxyHandler) resolveRoute(r *http.Request) (*routeEntry, string, error) {
	if route, bucket := h.routeFromHost(r.Host); route != nil {
		return route, bucket, nil
	}
	if route, bucket := h.routeFromPath(r.URL.Path); route != nil {
		return route, bucket, nil
	}
	if route, bucket, _ := h.routeFromAuthorization(r.Header.Get("Authorization")); route != nil {
		return route, bucket, nil
	}
	if h.defaultRoute != nil {
		return h.defaultRoute, h.defaultRoute.cfg.Bucket, nil
	}

	if bucket := bucketFromPathCandidate(r.URL.Path); bucket != "" {
		if _, ok := h.routesByBucket[normalizeBucketKey(bucket)]; !ok {
			return nil, "", fmt.Errorf("bucket %q recognized from request path but not found in config", bucket)
		}
	}

	if bucket := bucketFromHostCandidate(r.Host); bucket != "" {
		if _, ok := h.routesByBucket[normalizeBucketKey(bucket)]; !ok {
			return nil, "", fmt.Errorf("bucket %q recognized from request host but not found in config", bucket)
		}
	}

	return nil, "", fmt.Errorf("cannot determine bucket from request host/path/auth")
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
	if first, _, ok := strings.Cut(host, "."); ok && isLikelyBucketName(first) {
		if route, ok := h.routesByBucket[first]; ok {
			return route, route.cfg.Bucket
		}
	}
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
	bucket := bucketFromPathCandidate(path)
	if bucket == "" {
		return nil, ""
	}
	if route, ok := h.routesByBucket[normalizeBucketKey(bucket)]; ok {
		return route, route.cfg.Bucket
	}
	return nil, ""
}

func bucketFromPathCandidate(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return ""
	}
	first, _, _ := strings.Cut(trimmed, "/")
	first = strings.TrimSpace(first)
	if !isLikelyBucketName(first) {
		return ""
	}
	return first
}

func bucketFromHostCandidate(hostport string) string {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return ""
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

	if net.ParseIP(host) != nil {
		return ""
	}

	host = normalizeBucketKey(host)
	if host == "" {
		return ""
	}

	if strings.Contains(host, ".") {
		first, _, _ := strings.Cut(host, ".")
		first = strings.TrimSpace(first)
		if !isLikelyBucketName(first) {
			return ""
		}
		return first
	}
	if !isLikelyBucketName(host) {
		return ""
	}
	return host
}

func isLikelyBucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			continue
		}
		return false
	}
	first := name[0]
	last := name[len(name)-1]
	if !((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return false
	}
	if !((last >= 'a' && last <= 'z') || (last >= '0' && last <= '9')) {
		return false
	}
	return true
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

	rawLower := strings.ToLower(raw)
	if strings.HasPrefix(rawLower, "oss ") {
		cred := strings.TrimSpace(raw[4:])
		accessKeyID, _, ok := strings.Cut(cred, ":")
		if !ok {
			return ""
		}
		return strings.TrimSpace(accessKeyID)
	}

	if strings.HasPrefix(rawLower, "oss4-hmac-sha256") {
		idx := strings.Index(rawLower, "credential=")
		if idx < 0 {
			return ""
		}
		credentialPart := raw[idx+len("credential="):]
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

func isObjectMetaRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	_, ok := r.URL.Query()["objectMeta"]
	return ok
}

func normalizeObjectMetaGETResponseHeaders(h http.Header) {
	if h == nil {
		return
	}
	if size := h.Get("Content-Length"); size != "" {
		// For GET compatibility we return a valid empty response body, so downstream Content-Length
		// cannot keep OSS object-size metadata value. Preserve it in a separate header.
		if h.Get("X-Oss-Object-Size") == "" {
			h.Set("X-Oss-Object-Size", size)
		}
		h.Del("Content-Length")
	}
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
	trimmed = strings.TrimPrefix(trimmed, prefix)
	if trimmed == "" {
		return "/"
	}
	return "/" + trimmed
}

func (h *proxyHandler) sanitizeAndSign(origReq, req *http.Request, route *routeEntry, bucketName string) {
	removeHopByHopHeaders(req.Header)

	req.Host = req.URL.Host
	req.Header.Set("Host", req.URL.Host)
	req.Header.Del("Authorization")
	req.Header.Del("Date")

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

	auth := signV1(req, route.cfg.AccessKeyID, route.cfg.AccessKeySecret, bucketName)
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

func (h *proxyHandler) signAsV4(req *http.Request, route *routeEntry, bucketName string) {
	now := time.Now().UTC()
	signDate := now.Format("20060102")
	ossDate := now.Format("20060102T150405Z")
	region := route.cfg.Region
	if region == "" {
		region = inferRegion(route.cfg.Endpoint)
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

	signingKey := route.getOrDeriveV4SigningKey(signDate, region)
	sig := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	auth := fmt.Sprintf(
		"OSS4-HMAC-SHA256 Credential=%s/%s/%s/oss/aliyun_v4_request,Signature=%s",
		route.cfg.AccessKeyID, signDate, region, sig,
	)
	if os.Getenv("OSS_PROXY_DEBUG_SIGN") == "1" {
		log.Printf("v4 canonicalRequest:\n%s\nv4 stringToSign:\n%s\nv4 signature=%s", canonicalRequest, stringToSign, sig)
	}
	req.Header.Set("Authorization", auth)
}

func (r *routeEntry) getOrDeriveV4SigningKey(signDate, region string) []byte {
	r.v4SigningKeyMu.RLock()
	if r.v4SigningKeyDate == signDate && r.v4SigningRegion == region && len(r.v4SigningKey) > 0 {
		key := r.v4SigningKey
		r.v4SigningKeyMu.RUnlock()
		return key
	}
	r.v4SigningKeyMu.RUnlock()

	derived := deriveV4SigningKey(r.cfg.AccessKeySecret, signDate, region)
	r.v4SigningKeyMu.Lock()
	defer r.v4SigningKeyMu.Unlock()
	if r.v4SigningKeyDate == signDate && r.v4SigningRegion == region && len(r.v4SigningKey) > 0 {
		return r.v4SigningKey
	}
	r.v4SigningKeyDate = signDate
	r.v4SigningRegion = region
	r.v4SigningKey = append(r.v4SigningKey[:0], derived...)
	return r.v4SigningKey
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
		dst[k] = append([]string(nil), vals...)
	}
}

type limitedCaptureWriter struct {
	buf       []byte
	limit     int
	truncated bool
}

func newLimitedCaptureWriter(limit int) *limitedCaptureWriter {
	if limit < 0 {
		limit = 0
	}
	return &limitedCaptureWriter{
		buf:   make([]byte, 0, limit),
		limit: limit,
	}
}

func (w *limitedCaptureWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	remaining := w.limit - len(w.buf)
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		w.buf = append(w.buf, p[:remaining]...)
	}
	if len(w.buf) >= w.limit && len(p) > remaining {
		w.truncated = true
	}
	return len(p), nil
}

func (w *limitedCaptureWriter) Bytes() []byte {
	return w.buf
}

func (w *limitedCaptureWriter) Truncated() bool {
	return w.truncated
}

type ossErrorResponse struct {
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
	RequestID string `xml:"RequestId"`
	HostID    string `xml:"HostId"`
	EC        string `xml:"EC"`
}

func parseOSSErrorBody(body []byte) ossErrorResponse {
	var parsed ossErrorResponse
	if len(bytes.TrimSpace(body)) == 0 {
		return parsed
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return ossErrorResponse{}
	}
	return parsed
}
