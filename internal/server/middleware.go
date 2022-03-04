package server

import (
	"net/http"

	"github.com/some-programs/natbwmon/internal/log"
)

// AppHandler adds generic error handling to a handler func.
//
// A catch all error response writer handler for convinience.
//
// A handler func that writes it's own error response should typically not return an error.
//
type AppHandler func(http.ResponseWriter, *http.Request) error

func (fn AppHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rw := &responseWriter{ResponseWriter: w}
	if err := fn(rw, r); err != nil {
		if rw.hasWritten {
			logger := log.FromRequest(r)
			logger.Warn().Err(err).Msg("error returned to AppHandler after respose has been written to")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
}

// responseWriter is a http.responseWriter that tracks if it has been written to.
type responseWriter struct {
	http.ResponseWriter
	hasWritten bool
}

func (r *responseWriter) Write(b []byte) (int, error) {
	r.hasWritten = true
	return r.ResponseWriter.Write(b)
}

// maxBytesReaderMiddleware .
type maxBytesReaderMiddleware struct {
	h http.Handler
	N int64
}

func (b maxBytesReaderMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, b.N)
	b.h.ServeHTTP(w, r)
}

func MaxBytesReaderMiddleware(maxSize int64) func(h http.Handler) http.Handler {
	if maxSize <= 0 {
		log.Fatal().Msgf("maxSize cannot be equal or less than 0: %v", maxSize)
	}
	fn := func(h http.Handler) http.Handler {
		return maxBytesReaderMiddleware{h: h, N: maxSize}
	}
	return fn
}
