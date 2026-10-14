package es2plus_test

import (
	"rsp42/internal/api/es2plus"
	"rsp42/internal/metrics"
	"rsp42/internal/service"
)

// newES2PMetricsRegistry builds a registry with the vocabulary of every package
// involved, matching the production registry (the cli declares both). The
// ES2+ ACR path records a service-owned counter, so declaring only the ES2+
// names would (correctly) trip the registry's undeclared-metric panic.
func newES2PMetricsRegistry() *metrics.Registry {
	reg := metrics.NewRegistry()
	service.DescribeMetrics(reg)
	es2plus.DescribeMetrics(reg)
	return reg
}
