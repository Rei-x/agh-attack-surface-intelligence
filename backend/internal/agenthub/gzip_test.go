package agenthub

import (
	"bytes"
	"compress/gzip"
	"net/http/httptest"
	"testing"
)

func TestDecodeGzipBody(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"chunk":{"id":"c1","status":"DONE"},"observations":[]}`))
	_ = zw.Close()
	r := httptest.NewRequest("POST", "/api/v1/agent/jobs/x/chunks", &buf)
	r.Header.Set("Content-Encoding", "gzip")
	var up ChunkUpload
	if err := decode(r, &up); err != nil || up.Chunk.ID != "c1" {
		t.Fatalf("decode gzip: %v %+v", err, up)
	}

	plain := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte(`{"chunk":{"id":"c2"}}`)))
	if err := decode(plain, &up); err != nil || up.Chunk.ID != "c2" {
		t.Fatalf("decode plain: %v", err)
	}
	bad := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte("not gzip")))
	bad.Header.Set("Content-Encoding", "gzip")
	if err := decode(bad, &up); err == nil {
		t.Fatal("invalid gzip accepted")
	}
	br := httptest.NewRequest("POST", "/x", bytes.NewReader(nil))
	br.Header.Set("Content-Encoding", "br")
	if err := decode(br, &up); err == nil {
		t.Fatal("unsupported encoding accepted")
	}
}
