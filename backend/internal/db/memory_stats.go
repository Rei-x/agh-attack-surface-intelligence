package db

import (
	"encoding/json"
	"sort"
	"strings"
)

// CollectionStat is the serialized size of one collection of the in-memory store, as it is
// written into the encrypted snapshot (JSON, before gzip and the file-level AES-GCM seal).
// Strings dominate both the snapshot and the heap, so Bytes is also a good proxy for the
// live heap a collection holds after load.
type CollectionStat struct {
	Name  string `json:"name"`
	Items int    `json:"items"` // rows (for per-key lists: total nested rows)
	Bytes int64  `json:"bytes"`
	// Part marks a breakdown of a parent collection (already counted in the parent).
	Part bool `json:"part,omitempty"`
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// jsonSize returns the length of v's JSON encoding without keeping the encoding around.
func jsonSize(v any) int64 {
	var cw countWriter
	_ = json.NewEncoder(&cw).Encode(v)
	if cw.n > 0 {
		cw.n-- // Encode appends a newline
	}
	return cw.n
}

// mapSize sums the JSON size of every entry of m (key, value and separators), encoding one
// entry at a time so even a huge collection never needs one big buffer.
func mapSize[K comparable, V any](m map[K]V) int64 {
	var total int64 = 2
	for k, v := range m {
		total += jsonSize(k) + 2 + jsonSize(v)
	}
	return total
}

// CollectionStats reports per-collection item counts and serialized sizes, largest first.
// It holds the read lock while it measures, so use it from debugging tools only.
func (m *MemoryStore) CollectionStats() []CollectionStat {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []CollectionStat
	add := func(name string, items int, bytes int64) {
		out = append(out, CollectionStat{Name: name, Items: items, Bytes: bytes})
	}
	part := func(name string, items int, bytes int64) {
		out = append(out, CollectionStat{Name: name, Items: items, Bytes: bytes, Part: true})
	}

	add("crypto_keys", len(m.cryptoKeys), mapSize(m.cryptoKeys))
	add("roles", len(m.roles), mapSize(m.roles))
	add("users", len(m.users), mapSize(m.users))
	add("targets", len(m.targets), mapSize(m.targets))
	add("exclusions", len(m.exclusions), mapSize(m.exclusions))
	add("profiles", len(m.profiles), mapSize(m.profiles))

	add("scan_runs", len(m.scanRuns), mapSize(m.scanRuns))
	var xmlBytes int64
	xmlRuns := 0
	for _, r := range m.scanRuns {
		if r.RawNmapXMLEnc != "" {
			xmlRuns++
			xmlBytes += int64(len(r.RawNmapXMLEnc))
		}
	}
	part("scan_runs.raw_nmap_xml", xmlRuns, xmlBytes)

	chunkRows := 0
	var targetBytes, cmdBytes int64
	for _, list := range m.scanChunks {
		chunkRows += len(list)
		for _, c := range list {
			targetBytes += jsonSize(c.Targets)
			cmdBytes += jsonSize(c.NmapCommands)
		}
	}
	add("scan_chunks", chunkRows, mapSize(m.scanChunks))
	part("scan_chunks.targets", chunkRows, targetBytes)
	part("scan_chunks.nmap_commands", chunkRows, cmdBytes)

	add("hosts", len(m.hosts), mapSize(m.hosts))
	add("host_by_ip_hmac", len(m.hostByIPHMAC), mapSize(m.hostByIPHMAC))
	add("services", len(m.services), mapSize(m.services))

	obsRows := 0
	var obsHTTP, obsBanner int64
	for _, list := range m.observations {
		obsRows += len(list)
		for _, o := range list {
			obsHTTP += int64(len(o.HTTPEnc))
			obsBanner += int64(len(o.BannerEnc))
		}
	}
	add("observations", obsRows, mapSize(m.observations))
	part("observations.http", obsRows, obsHTTP)
	part("observations.banner", obsRows, obsBanner)

	ovRows := 0
	for _, f := range m.overrides {
		ovRows += len(f)
	}
	add("overrides", ovRows, mapSize(m.overrides))

	add("changes", len(m.changes), mapSize(m.changes))
	var beforeAfter int64
	for _, c := range m.changes {
		beforeAfter += int64(len(c.BeforeEnc) + len(c.AfterEnc))
	}
	part("changes.before_after", len(m.changes), beforeAfter)

	add("scan_snapshots", len(m.snapshots), mapSize(m.snapshots))
	add("signatures", len(m.signatures), mapSize(m.signatures))
	add("dd_exports", len(m.ddExports), jsonSize(m.ddExports))
	add("audit_logs", len(m.auditLogs), jsonSize(m.auditLogs))
	add("schedule_states", len(m.scheduleStates), mapSize(m.scheduleStates))

	// Settings documents grouped by key family (run_telemetry:<run> is one per run).
	type agg struct {
		items int
		bytes int64
	}
	groups := map[string]*agg{}
	for k, v := range m.settings {
		g := k
		if i := strings.IndexByte(k, ':'); i > 0 {
			g = k[:i] + ":*"
		}
		a := groups[g]
		if a == nil {
			a = &agg{}
			groups[g] = a
		}
		a.items++
		a.bytes += jsonSize(k) + 2 + int64(len(v)) + 2
	}
	for g, a := range groups {
		add("settings["+g+"]", a.items, a.bytes)
	}

	// Largest collections first, each followed by its own breakdown rows.
	var parents []CollectionStat
	parts := map[string][]CollectionStat{}
	for _, s := range out {
		if s.Part {
			parent := s.Name[:strings.IndexByte(s.Name, '.')]
			parts[parent] = append(parts[parent], s)
			continue
		}
		parents = append(parents, s)
	}
	sort.SliceStable(parents, func(i, j int) bool { return parents[i].Bytes > parents[j].Bytes })
	sorted := make([]CollectionStat, 0, len(out))
	for _, p := range parents {
		sorted = append(sorted, p)
		sorted = append(sorted, parts[p.Name]...)
	}
	return sorted
}
