package es2plus

import "rsp42/internal/metrics"

// DescribeMetrics declares the metrics the ES2+ handler and callback queue emit.
// Keeping the vocabulary beside the emitters means a new metric cannot be added
// without also declaring its type and help text: metrics.Registry refuses an
// undeclared name.
func DescribeMetrics(reg *metrics.Registry) {
	reg.Describe("rsp42_es12_register_failures_total", metrics.Counter,
		"SM-DS event registration failures by tenant.")
	reg.Describe("rsp42_es2p_profile_type_unparsed_total", metrics.Counter,
		"downloadOrder requests whose profileType did not resolve to a tenant template, by tenant.")
}
