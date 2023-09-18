package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/moov-io/base/admin"
	"github.com/moov-io/base/http/bind"
	"github.com/moov-io/base/log"
	"github.com/moov-io/dukpt"
	"github.com/moov-io/dukpt/pkg/server"

	kitlog "github.com/go-kit/log"
)

var (
	httpAddr  = flag.String("http.addr", bind.HTTP("dukpt"), "HTTP listen address")
	adminAddr = flag.String("admin.addr", bind.Admin("dukpt"), "Admin HTTP listen address")

	flagLogFormat = flag.String("log.format", "", "Format for log lines (Options: json, plain")

	svc     server.Service
	handler http.Handler
)

func main() {
	flag.Parse()

	// Setup logging, default to stdout
	var kitlogger kitlog.Logger
	if v := os.Getenv("LOG_FORMAT"); v != "" {
		*flagLogFormat = v
	}
	if *flagLogFormat == "json" {
		kitlogger = kitlog.NewJSONLogger(kitlog.NewSyncWriter(os.Stdout))
	} else {
		kitlogger = kitlog.NewLogfmtLogger(kitlog.NewSyncWriter(os.Stdout))
	}

	logger := log.NewLogger(kitlogger)
	logger.Logf("Starting dukpt server version %s", dukpt.Version)

	// Setup underlying dukpt service
	r := server.NewRepositoryInMemory(logger)
	svc = server.NewService(r)

	// Create HTTP server
	handler = server.MakeHTTPHandler(svc)

	// Listen for application termination.
	errs := make(chan error)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errs <- fmt.Errorf("%s", <-c)
	}()

	readTimeout, _ := time.ParseDuration("30s")
	writTimeout, _ := time.ParseDuration("30s")
	idleTimeout, _ := time.ParseDuration("60s")

	// Check to see if our -http.addr flag has been overridden
	if v := os.Getenv("HTTP_BIND_ADDRESS"); v != "" {
		*httpAddr = v
	}

	serve := &http.Server{
		Addr:    *httpAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			InsecureSkipVerify:       false,
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS12,
		},
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: readTimeout,
		WriteTimeout:      writTimeout,
		IdleTimeout:       idleTimeout,
	}
	shutdownServer := func() {
		if err := serve.Shutdown(context.TODO()); err != nil {
			logger.LogError(err)
		}
	}

	// Check to see if our -admin.addr flag has been overridden
	if v := os.Getenv("HTTP_ADMIN_BIND_ADDRESS"); v != "" {
		*adminAddr = v
	}

	// Admin server (metrics and debugging)
	adminServer, _ := admin.New(admin.Opts{Addr: *adminAddr})
	adminServer.AddVersionHandler(dukpt.Version) // Setup 'GET /version'
	go func() {
		logger.Logf("admin listening on %s", adminServer.BindAddr())
		if err := adminServer.Listen(); err != nil {
			err = fmt.Errorf("problem starting admin http: %v", err)
			logger.LogError(err)
			errs <- err
		}
	}()
	defer adminServer.Shutdown()

	// Start main HTTP server
	go func() {
		if certFile, keyFile := os.Getenv("HTTPS_CERT_FILE"), os.Getenv("HTTPS_KEY_FILE"); certFile != "" && keyFile != "" {
			logger.Logf("startup binding to %s for secure HTTP server", *httpAddr)
			if err := serve.ListenAndServeTLS(certFile, keyFile); err != nil {
				errs <- err
				logger.LogError(err)
			}
		} else {
			logger.Logf("startup binding to %s for HTTP server", *httpAddr)
			if err := serve.ListenAndServe(); err != nil {
				errs <- err
				logger.LogError(err)
			}
		}
	}()

	if err := <-errs; err != nil {
		shutdownServer()
		logger.LogError(err)
	}
}
