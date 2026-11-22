package defectdojo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// A page of full DefectDojo findings easily exceeds 4 MB and must still be read whole.
func TestListPagedReadsLargePages(t *testing.T) {
	pad := strings.Repeat("x", 30000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString(`{"count":200,"next":null,"results":[`)
		for i := 0; i < 200; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"id":%d,"unique_id_from_tool":"u%d","description":"%s"}`, i+1, i, pad)
		}
		b.WriteString("]}")
		_, _ = w.Write([]byte(b.String()))
	}))
	defer srv.Close()
	type row struct {
		ID int `json:"id"`
	}
	c := &Client{}
	rows, err := listPaged[row](context.Background(), c, &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}, "/api/v2/findings/?test=1", findingsPageSize)
	if err != nil {
		t.Fatalf("large page: %v", err)
	}
	if len(rows) != 200 {
		t.Fatalf("rows: %d", len(rows))
	}
}
