package agenthub

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
)

// maxDecodedBody bounds a decompressed agent upload (a gzip bomb cannot exhaust memory).
const maxDecodedBody = 256 << 20

// requestBody returns the request body, transparently decompressing Content-Encoding: gzip
// (agents compress large chunk uploads that carry screenshots).
func requestBody(r *http.Request) (io.Reader, func(), error) {
	enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		return r.Body, func() {}, nil
	case "gzip":
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, nil, errors.New("invalid gzip body")
		}
		return io.LimitReader(zr, maxDecodedBody), func() { _ = zr.Close() }, nil
	default:
		return nil, nil, errors.New("unsupported Content-Encoding " + enc)
	}
}
