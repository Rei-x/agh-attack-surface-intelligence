package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCgroupMemoryLimit(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	v2 := write("memory.max", "1610612736\n")
	unlimitedV2 := write("unlimited.max", "max\n")
	unlimitedV1 := write("limit_in_bytes", "9223372036854771712\n")
	missing := filepath.Join(dir, "missing")

	cases := []struct {
		files []string
		want  int64
	}{
		{[]string{v2}, 1610612736},
		{[]string{missing, unlimitedV2, v2}, 1610612736},
		{[]string{unlimitedV2, unlimitedV1}, 0},
		{[]string{missing}, 0},
	}
	for i, c := range cases {
		if got := readCgroupMemoryLimit(c.files); got != c.want {
			t.Fatalf("case %d: got %d, want %d", i, got, c.want)
		}
	}
}
