package db

// ServiceOnly returns the service-level terms of the query (port, tech, title, admin,
// eol, ...) without free text or host-level terms, for filtering single services of hosts
// that already matched the full query (e.g. the screenshot gallery). nil when there are none.
func (q *AssetQuery) ServiceOnly() *AssetQuery {
	if q == nil {
		return nil
	}
	out := &AssetQuery{}
	for _, t := range q.Terms {
		if serviceLevelKeys[t.Key] {
			out.Terms = append(out.Terms, t)
		}
	}
	if len(out.Terms) == 0 {
		return nil
	}
	return out
}
