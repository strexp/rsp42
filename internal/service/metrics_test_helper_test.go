package service

import "rsp42/internal/metrics"

// newServiceMetricsRegistry builds a registry that declares the service metric
// vocabulary, matching what the composition root does in production.
func newServiceMetricsRegistry() *metrics.Registry {
	reg := metrics.NewRegistry()
	DescribeMetrics(reg)
	return reg
}
