// Command calibrate measures how well AegisASI's technology confidence is
// calibrated against the scale lab ground truth (lab/scale, GET /truth).
//
// Collect (must run where the lab's 10.66.0.0/18 is routable, e.g. a container
// on aegis-asi-net with the route installed):
//
//	calibrate -truth http://172.28.0.66:9900/truth -dump obs.jsonl
//
// Replay offline with the current fusion code (no network):
//
//	calibrate -replay obs.jsonl
//
// The report is a reliability table (predicted confidence bin vs observed
// precision) and the precision of every evidence channel when it is the only
// channel supporting a detection, which is exactly the noisy-OR likelihood
// weight P(tech | that evidence alone).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/fingerprint"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/intelligence"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

// Minimal subset of lab/scale/internal/truth (separate module).
type truthDoc struct {
	Hosts []struct {
		IP        string `json:"ip"`
		Alive     bool   `json:"alive"`
		Flapping  bool   `json:"flapping"`
		TimeOfDay *struct {
			Start int `json:"start"`
		} `json:"time_of_day"`
		Services []struct {
			Port         int       `json:"port"`
			Service      string    `json:"service"`
			Technologies []string  `json:"technologies"`
			HTTP         *struct{} `json:"http"`
		} `json:"services"`
	} `json:"hosts"`
}

type record struct {
	IP     string                 `json:"ip"`
	Port   int                    `json:"port"`
	Truth  []string               `json:"truth"`
	Obs    domain.ObservedService `json:"obs"`
	ErrMsg string                 `json:"err,omitempty"`
}

func main() {
	truthURL := flag.String("truth", "http://172.28.0.66:9900/truth", "lab ground truth URL")
	dump := flag.String("dump", "", "write collected observations (JSONL) here")
	replay := flag.String("replay", "", "replay observations from JSONL instead of probing")
	conc := flag.Int("c", 64, "probe concurrency")
	flag.Parse()

	var recs []record
	if *replay != "" {
		recs = load(*replay)
	} else {
		recs = collect(*truthURL, *conc)
		if *dump != "" {
			save(*dump, recs)
		}
	}
	report(recs)
}

func collect(url string, conc int) []record {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	var td truthDoc
	if err := json.NewDecoder(resp.Body).Decode(&td); err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()

	var jobs []record
	for _, h := range td.Hosts {
		if !h.Alive || h.Flapping || h.TimeOfDay != nil {
			continue
		}
		for _, s := range h.Services {
			if s.HTTP == nil {
				continue
			}
			jobs = append(jobs, record{IP: h.IP, Port: s.Port, Truth: s.Technologies,
				Obs: domain.ObservedService{Port: s.Port, Protocol: "tcp", State: "open", ServiceName: s.Service}})
		}
	}
	log.Printf("probing %d HTTP services", len(jobs))
	opts := fingerprint.DefaultOptions()
	opts.DisableJARM = true
	opts.Timeout = 6 * time.Second
	fp := fingerprint.New(opts)
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(r *record) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := fp.Probe(ctx, r.IP, r.Port, "", nil)
			if err != nil {
				r.ErrMsg = err.Error()
				return
			}
			r.Obs.HTTP = res
		}(&jobs[i])
	}
	wg.Wait()
	return jobs
}

func save(path string, recs []record) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, r := range recs {
		_ = enc.Encode(r)
	}
	_ = w.Flush()
}

func load(path string) []record {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var out []record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 8<<20), 8<<20)
	for sc.Scan() {
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// ---- name normalisation, mirrors lab/scale/cmd/scorer normTech ----

var genericTech = map[string]bool{
	"admin panel / management console": true, "authentication / login portal": true, "exposed database service": true,
	"exposed docker engine api": true, "admin console": true, "staging / debug environment": true,
}

var techAlias = map[string]string{
	"apache http server": "apache", "apache httpd": "apache", "apache": "apache", "microsoft iis": "iis", "iis": "iis",
	"microsoft-iis": "iis", "apache tomcat": "tomcat", "tomcat": "tomcat", "nginx": "nginx", "roundcube webmail": "roundcube",
	"hp printer / embedded web server": "hp-printer", "brother printer web interface": "brother-printer",
	"hikvision ip camera / nvr": "hikvision", "mikrotik routeros": "mikrotik-routeros", "synology dsm": "synology-dsm",
	"server bmc (dell idrac / hpe ilo)": "idrac", "spring boot": "spring-boot", "asp.net": "asp.net", "express": "express",
	"node.js": "node.js", "canon printer / remote ui": "canon-printer", "vue.js": "vue.js", "next.js": "next.js",
	"jetty": "jetty", "php": "php", "elastic": "elasticsearch", "elasticsearch": "elasticsearch",
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9.+-]+`)

func normTech(name, category string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch strings.ToLower(category) {
	case "staging", "interesting_header", "interesting_cookie", "tls":
		return "", false
	}
	if genericTech[n] {
		return "", false
	}
	if a, ok := techAlias[n]; ok {
		return a, true
	}
	return strings.Trim(nonAlnum.ReplaceAllString(n, "-"), "-"), true
}

// ---- report ----

type pred struct {
	conf    int
	correct bool
	types   []string
	name    string
}

func report(recs []record) {
	eng := signatures.NewEngine(nil)
	var preds []pred
	probed, failed, truthTechs, found := 0, 0, 0, 0
	for _, r := range recs {
		if r.Obs.HTTP == nil {
			failed++
			continue
		}
		probed++
		truth := map[string]bool{}
		for _, t := range r.Truth {
			truth[t] = true
		}
		truthTechs += len(truth)
		matches := eng.Evaluate(r.Obs)
		techs := intelligence.DetectTechnologies(r.Obs, matches, 1)
		hit := map[string]bool{}
		for _, t := range techs {
			n, ok := normTech(t.Name, t.Category)
			if !ok {
				continue
			}
			set := map[string]bool{}
			for _, ev := range t.Evidence {
				if ev.SignalType != "conflict" {
					set[ev.SignalType] = true
				}
			}
			types := make([]string, 0, len(set))
			for k := range set {
				types = append(types, k)
			}
			sort.Strings(types)
			preds = append(preds, pred{conf: t.Confidence, correct: truth[n], types: types, name: n})
			if truth[n] {
				hit[n] = true
			}
		}
		found += len(hit)
	}

	fmt.Printf("services probed: %d (failed %d); truth technologies: %d; recovered: %d (recall %.1f%%); predictions: %d\n\n",
		probed, failed, truthTechs, found, 100*float64(found)/math.Max(1, float64(truthTechs)), len(preds))

	bins := []struct{ lo, hi int }{{0, 49}, {50, 59}, {60, 69}, {70, 79}, {80, 89}, {90, 94}, {95, 100}}
	fmt.Println("| predicted confidence | n | mean predicted | observed precision | gap |")
	fmt.Println("|---|---|---|---|---|")
	ece, oce, total := 0.0, 0.0, 0
	for _, b := range bins {
		n, ok, sum := 0, 0, 0
		for _, p := range preds {
			if p.conf >= b.lo && p.conf <= b.hi {
				n++
				sum += p.conf
				if p.correct {
					ok++
				}
			}
		}
		if n == 0 {
			fmt.Printf("| %d-%d%% | 0 | – | – | – |\n", b.lo, b.hi)
			continue
		}
		mean := float64(sum) / float64(n) / 100
		prec := float64(ok) / float64(n)
		ece += float64(n) * math.Abs(mean-prec)
		oce += float64(n) * math.Max(0, mean-prec)
		total += n
		fmt.Printf("| %d-%d%% | %d | %.0f%% | %.0f%% (%d/%d) | %+.0f pp |\n", b.lo, b.hi, n, 100*mean, 100*prec, ok, n, 100*(prec-mean))
	}
	if total > 0 {
		fmt.Printf("\nExpected calibration error (ECE): %.1f pp; over-confidence part (OCE): %.1f pp\n\n", 100*ece/float64(total), 100*oce/float64(total))
	}

	// Precision of each evidence channel when it is the only channel.
	type agg struct{ n, ok, conf int }
	single := map[string]*agg{}
	multi := &agg{}
	for _, p := range preds {
		if len(p.types) == 1 {
			a := single[p.types[0]]
			if a == nil {
				a = &agg{}
				single[p.types[0]] = a
			}
			a.n++
			a.conf += p.conf
			if p.correct {
				a.ok++
			}
		} else if len(p.types) > 1 {
			multi.n++
			multi.conf += p.conf
			if p.correct {
				multi.ok++
			}
		}
	}
	keys := make([]string, 0, len(single))
	for k := range single {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("| evidence channel (alone) | n | mean predicted | observed precision | Laplace (k+1)/(n+2) |")
	fmt.Println("|---|---|---|---|---|")
	for _, k := range keys {
		a := single[k]
		fmt.Printf("| %s | %d | %.0f%% | %.0f%% | %.2f |\n", k, a.n, float64(a.conf)/float64(a.n), 100*float64(a.ok)/float64(a.n), float64(a.ok+1)/float64(a.n+2))
	}
	if multi.n > 0 {
		fmt.Printf("| ≥2 independent channels | %d | %.0f%% | %.0f%% | %.2f |\n", multi.n, float64(multi.conf)/float64(multi.n), 100*float64(multi.ok)/float64(multi.n), float64(multi.ok+1)/float64(multi.n+2))
	}

	// Most frequent false positives (to inspect).
	fp := map[string]int{}
	for _, p := range preds {
		if !p.correct {
			fp[fmt.Sprintf("%s [%s] %d%%", p.name, strings.Join(p.types, "+"), p.conf/10*10)]++
		}
	}
	type kv struct {
		k string
		v int
	}
	var fps []kv
	for k, v := range fp {
		fps = append(fps, kv{k, v})
	}
	sort.Slice(fps, func(i, j int) bool { return fps[i].v > fps[j].v })
	if len(fps) > 0 {
		fmt.Println("\nTop false positives (name [channels] conf-bin):")
		for i, e := range fps {
			if i >= 15 {
				break
			}
			fmt.Printf("  %4d  %s\n", e.v, e.k)
		}
	}
}
