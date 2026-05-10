package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)


type Config struct {
	Services map[string]string `yaml:"services"`
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func newIPLimiter() *ipLimiter {
	l := &ipLimiter{limiters: make(map[string]*rate.Limiter)}
	// clean up stale IPs every 10 minutes
	go func() {
		for range time.Tick(10 * time.Minute) {
			l.mu.Lock()
			l.limiters = make(map[string]*rate.Limiter)
			l.mu.Unlock()
		}
	}()
	return l
}

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[ip]; ok {
		return lim
	}
	lim := rate.NewLimiter(rate.Every(time.Minute/20), 20) // 20 req/min burst 20
	l.limiters[ip] = lim
	return lim
}

var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,50}$`)

type server struct {
	apiKey     []byte
	configPath string
	limiter    *ipLimiter
	httpClient *http.Client
}

func newServer(apiKey, configPath string) *server {
	return &server{
		apiKey:     []byte(apiKey),
		configPath: configPath,
		limiter:    newIPLimiter(),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
		},
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != "/status" {
		http.NotFound(w, r)
		return
	}


	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.limiter.get(ip).Allow() {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	key := r.Header.Get("X-API-Key")
	mac := hmac.New(sha256.New, s.apiKey)
	mac.Write([]byte(key))
	got := mac.Sum(nil)
	mac.Reset()
	mac.Write(s.apiKey)
	want := mac.Sum(nil)

	if !hmac.Equal(got, want) {
		time.Sleep(500 * time.Millisecond) // slow down brute force
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	service := r.URL.Query().Get("service")
	if !serviceNameRe.MatchString(service) {
		http.Error(w, "invalid service name", http.StatusBadRequest)
		return
	}

	cfg, err := loadConfig(s.configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	url, ok := cfg.Services[service]
	if !ok {
		http.NotFound(w, r)
		return
	}

	online := s.ping(url)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"service": service,
		"online":  online,
	})
}

func (s *server) ping(url string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Info("ping", "url", url, "error", err)
		return false
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		slog.Info("ping", "url", url, "error", err)
		return false
	}
	resp.Body.Close()

	slog.Info("ping", "url", url, "status code", resp.StatusCode)

	return resp.StatusCode < 500
}

func main() {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		slog.Error("API_KEY env var is required")
		os.Exit(1)
	}

	configPath := os.Getenv("SERVICES_FILE")
	if configPath == "" {
		configPath = "/services.yaml"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              "0.0.0.0:" + port,
		Handler:           newServer(apiKey, configPath),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes:    1 << 13, // 8KB
	}

	slog.Info("starting status checker", "port", port)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}
