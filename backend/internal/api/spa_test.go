package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestServeSPAFromFSSubsiteIndex(t *testing.T) {
	s := &Server{cfg: Config{StaticFS: fstest.MapFS{
		"index.html":      {Data: []byte("spa")},
		"deck/index.html": {Data: []byte("deck")},
		"deck/deck.css":   {Data: []byte("css")},
		"img/logo.svg":    {Data: []byte("svg")},
	}}}

	get := func(p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.serveSPAFromFS(rec, httptest.NewRequest(http.MethodGet, p, nil))
		return rec
	}

	cases := []struct {
		path, body string
		code       int
	}{
		{"/deck/", "deck", http.StatusOK},
		{"/deck/deck.css", "css", http.StatusOK},
		{"/", "spa", http.StatusOK},
		{"/scans", "spa", http.StatusOK},
		{"/img/", "spa", http.StatusOK},
	}
	for _, c := range cases {
		rec := get(c.path)
		if rec.Code != c.code || strings.TrimSpace(rec.Body.String()) != c.body {
			t.Errorf("%s: got %d %q, want %d %q", c.path, rec.Code, rec.Body.String(), c.code, c.body)
		}
	}

	if rec := get("/deck"); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/deck/" {
		t.Errorf("/deck: got %d Location %q, want 301 to /deck/", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get("/deck/index.html"); rec.Code != http.StatusMovedPermanently {
		t.Errorf("/deck/index.html: got %d, want a redirect to /deck/", rec.Code)
	}
}
