// Copyright 2026 Flant JSC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh_testing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deckhouse/lib-dhctl/pkg/log"
	"github.com/deckhouse/lib-dhctl/pkg/retry"
	"github.com/name212/govalue"
	"github.com/stretchr/testify/require"
)

const HealthzPath = "/healthz"

type PrefixLogger struct {
	log.Logger
	prefix  string
	address string
}

func newPrefixLoggerWithAddress(logger log.Logger, address string) *PrefixLogger {
	l := NewPrefixLogger(logger)
	l.address = address
	return l.WithPrefix("")
}

func NewPrefixLogger(logger log.Logger) *PrefixLogger {
	l := &PrefixLogger{
		Logger: logger,
	}

	return l.WithPrefix("")
}

func (l *PrefixLogger) Log(write func(string, ...any), f string, args ...any) {
	if l.prefix != "" {
		f = l.prefix + ": " + f
	}

	write(f, args...)
}

func (l *PrefixLogger) LogError(f string, args ...any) {
	l.Log(l.ErrorF, f, args...)
}

func (l *PrefixLogger) addAddressForPrefix(p string) string {
	if p == "" {
		return l.address
	}

	if l.address != "" {
		return fmt.Sprintf("%s (%s)", p, l.address)
	}

	return p
}

func (l *PrefixLogger) WithPrefix(p string) *PrefixLogger {
	l.prefix = l.addAddressForPrefix(p)
	return l
}

type HTTPHandler struct {
	Path   string
	Handle func(w http.ResponseWriter, r *http.Request, logger *PrefixLogger)
}

func NewSimpleHTTPHandler(path string, response string) *HTTPHandler {
	return &HTTPHandler{
		Path: path,
		Handle: func(w http.ResponseWriter, r *http.Request, logger *PrefixLogger) {
			_, err := fmt.Fprintf(w, response)
			status := http.StatusOK
			if err != nil {
				logger.LogError("Error writing %s response: %v", r.URL.Path, err)
				status = http.StatusInternalServerError
			}
			w.WriteHeader(status)
		},
	}
}

func (h *HTTPHandler) IsValid() error {
	if h.Path == "" {
		return errors.New("missing path for handler")
	}

	if !strings.HasPrefix(h.Path, "/") {
		return fmt.Errorf("path '%s' must start with a slash", h.Path)
	}

	if govalue.Nil(h.Handle) {
		return fmt.Errorf("handle is nil for path %s", h.Path)
	}

	return nil
}

type HTTPServer struct {
	mux     *http.ServeMux
	server  *http.Server
	logger  *PrefixLogger
	address string
	stopped bool
}

func MustStartHTTPServer(t *testing.T, test *Test, port int, handlers ...*HTTPHandler) *HTTPServer {
	server := NewHTTPServer(port, test.Logger, handlers...).WithLogPrefix(test.TestName)
	err := server.Start(true)
	require.NoError(t, err)
	server.RegisterCleanup(t)

	return server
}

func NewHTTPServer(port int, logger *log.InMemoryLogger, handlers ...*HTTPHandler) *HTTPServer {
	mux := http.NewServeMux()

	address := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	server := &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	res := &HTTPServer{
		mux:     mux,
		server:  server,
		logger:  newPrefixLoggerWithAddress(logger, address).WithPrefix(""),
		address: address,
	}

	healthz := NewSimpleHTTPHandler(HealthzPath, "OK\n")

	fullHandlers := append([]*HTTPHandler{healthz}, handlers...)
	for _, h := range fullHandlers {
		res.AddHandler(h)
	}

	return res
}

func (s *HTTPServer) WithLogPrefix(p string) *HTTPServer {
	s.logger.WithPrefix(p)
	return s
}

func (s *HTTPServer) AddHandler(handler *HTTPHandler) {
	if err := handler.IsValid(); err != nil {
		s.logger.LogError("Handler %s is not valid: %v", handler.Path, err)
		return
	}

	if s.stopped {
		s.logger.Log(s.logger.WarnF, "AddHandler %s: server already stopped", handler.Path)
		return
	}

	s.mux.HandleFunc(handler.Path, func(writer http.ResponseWriter, request *http.Request) {
		handler.Handle(writer, request, s.logger)
	})
}

func (s *HTTPServer) Start(waitStart bool) error {
	go func() {
		s.logger.Log(s.logger.InfoF, "Starting HTTP server")
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.LogError("Error starting HTTP server: %v", err)
		}
	}()

	if !waitStart {
		return nil
	}

	url := fmt.Sprintf("http://%s%s", s.address, HealthzPath)

	loop := retry.NewEmptyParams(
		retry.WithName(fmt.Sprintf("Check HTTP server %s started", s.logger.prefix)),
		retry.WithAttempts(10),
		retry.WithWait(500*time.Millisecond),
		retry.WithLogger(s.logger.Logger),
	)

	_, err := DoGetRequest(url, loop, s.logger)
	if err != nil {
		err = fmt.Errorf("error starting HTTP server: %w", err)

		errStop := s.Stop()
		if errStop != nil {
			err = fmt.Errorf("%w and Stop error %w", err, errStop)
		}

		s.logger.LogError("%v", err)
		return err
	}

	return nil
}

func (s *HTTPServer) Stop() error {
	if s.stopped {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	defer cancel()

	err := s.server.Shutdown(ctx)
	if err != nil {
		s.logger.LogError("Error shutting down server: %v", err)
		return err
	}

	s.stopped = true
	s.logger.Log(s.logger.InfoF, "Server stopped")
	return nil
}

func (s *HTTPServer) RegisterCleanup(t *testing.T) {
	t.Cleanup(func() {
		if err := s.Stop(); err != nil {
			s.logger.LogError("Error cleanup server: %v", err)
		}
	})
}

func DoGetRequest(url string, loop retry.Params, logger *PrefixLogger) (string, error) {
	if url == "" {
		return "", errors.New("missing url for GET request")
	}

	if govalue.Nil(loop) {
		return "", errors.New("loop params is nil for GET request")
	}

	if govalue.Nil(logger) {
		return "", errors.New("logger is nil for GET request")
	}

	logError := func(msg string, err error) error {
		logger.LogError("Error GET %s request. %s: %v", url, msg, err)
		return err
	}

	response := ""

	if loop.Name() == retry.NotSetName {
		loop.Clone().WithName(fmt.Sprintf("Do GET request %s", url))
	}

	err := retry.NewLoopWithParams(loop).Run(func() error {
		client := &http.Client{}

		ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Second)
		defer cancel() // Ensure the context is canceled to release resources

		// Create a new HTTP GET request with the context
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return logError("creating", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return logError("do", err)
		}

		defer func() {
			if err := resp.Body.Close(); err != nil {
				_ = logError("closing body", err)
			}
		}()

		responseBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return logError("reading response body", err)
		}

		response = string(responseBytes)
		return nil
	})

	if err != nil {
		return "", err
	}

	return response, nil
}
