// Package metrics implements the small Prometheus-compatible metrics registry
// exposed on the admin listener at /metrics.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Kind is a Prometheus metric type.
type Kind string

// Metric kinds.
const (
	Counter Kind = "counter"
	Gauge   Kind = "gauge"
)

// Registry collects counters and gauges and renders them in the Prometheus text
// exposition format. The zero value is not usable; call NewRegistry.
type Registry struct {
	mu     sync.Mutex
	order  []string
	meta   map[string]Kind
	help   map[string]string
	values map[string]map[string]float64 // name -> canonical labels -> value
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		meta:   map[string]Kind{},
		help:   map[string]string{},
		values: map[string]map[string]float64{},
	}
}

// Describe declares a metric's type and help text. Declaring the same name twice
// is a no-op.
func (r *Registry) Describe(name string, kind Kind, help string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.meta[name]; !ok {
		r.meta[name] = kind
		r.help[name] = help
		r.order = append(r.order, name)
	}
}

// Inc increments a counter by one.
func (r *Registry) Inc(name string, labels map[string]string) { r.Add(name, labels, 1) }

// Add adds delta to a counter or gauge.
func (r *Registry) Add(name string, labels map[string]string, delta float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.meta[name]; !ok {
		r.meta[name] = Counter
		r.order = append(r.order, name)
	}
	key := labelKey(labels)
	if r.values[name] == nil {
		r.values[name] = map[string]float64{}
	}
	r.values[name][key] += delta
}

// Set assigns a gauge value.
func (r *Registry) Set(name string, labels map[string]string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.meta[name]; !ok {
		r.meta[name] = Gauge
		r.order = append(r.order, name)
	}
	if r.values[name] == nil {
		r.values[name] = map[string]float64{}
	}
	r.values[name][labelKey(labels)] = value
}

// Render produces the Prometheus text exposition.
func (r *Registry) Render() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for _, name := range r.order {
		kind := r.meta[name]
		if h := r.help[name]; h != "" {
			fmt.Fprintf(&b, "# HELP %s %s\n", name, h)
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", name, kind)
		keys := make([]string, 0, len(r.values[name]))
		for k := range r.values[name] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s%s %s\n", name, k, formatFloat(r.values[name][k]))
		}
	}
	return b.String()
}

// Collector refreshes derived gauges at scrape time.
type Collector func(*Registry)

// Handler serves the registry in the Prometheus text format, running the
// collectors first.
func Handler(reg *Registry, collectors ...Collector) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for _, c := range collectors {
			if c != nil {
				c(reg)
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(reg.Render()))
	}
}

// labelKey renders labels deterministically as `{a="1",b="2"}`.
func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", k, labels[k])
	}
	b.WriteByte('}')
	return b.String()
}

func formatFloat(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
