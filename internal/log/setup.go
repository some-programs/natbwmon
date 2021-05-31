package log

import (
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
	zlog "github.com/rs/zerolog/log"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	zerolog.TimeFieldFormat = time.RFC3339Nano
	stdlog.SetFlags(stdlog.Lshortfile)
	setup()
}

func setup() {
	stdlog.SetOutput(
		LoggerWithoutCaller.
			With().
			Str("module", "stdlog").
			Str("level", "info").
			Logger())
	zlog.Logger = Logger
}

// SetDiscardLogger sets global log level to trace and log to a ioutil.Discard writer.
// Use in tests to ensure that writing logs don't panic and are sileced.
func SetDiscardLogger() {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	Logger = zerolog.New(ioutil.Discard)
	LoggerWithoutCaller = zerolog.New(ioutil.Discard)
	setup()
}

// SetNonBlockingLogger sets up a logger with a non blocking writer
func SetNonBlockingLogger(w io.Writer) {
	wr := diode.NewWriter(w, 1000, 10*time.Millisecond, func(missed int) {
		fmt.Printf("Logger Dropped %d messages", missed)
	})
	LoggerWithoutCaller = zerolog.New(wr).With().Timestamp().Logger()
	Logger = LoggerWithoutCaller.With().Caller().Logger()
	setup()
}

// SetBlockingLogger sets up a logger with a blocking writer
func SetBlockingLogger(w io.Writer) {
	LoggerWithoutCaller = zerolog.New(w).With().Timestamp().Logger()
	Logger = LoggerWithoutCaller.With().Caller().Logger()
	setup()
}

// SetConsoleLogger sets up logging for console logging (developmnet)
func SetConsoleLogger() {
	wr := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "15:04:05.000",
	}
	LoggerWithoutCaller = zerolog.New(wr).With().Timestamp().Logger()
	Logger = LoggerWithoutCaller.With().Caller().Logger()
	setup()
}
