package service

import "rsp42/internal/metrics"

// DescribeMetrics declares the metrics the service layer emits, so a registry
// can be built with the full vocabulary before the first event. The registry
// refuses to record an undeclared name (see metrics.Registry.Add), which makes a
// typo a loud failure instead of a silently missing series.
func DescribeMetrics(reg *metrics.Registry) {
	// Incremented once per outbound ES2+ HandleDownloadProgressInfo, i.e. once
	// per download/install outcome point, labelled by tenant, notification point
	// and status. The name is the one esim42's dashboards reference for
	// "downloads by tenant, point and status" (docs/interfaces.md).
	reg.Describe("rsp42_downloads_total", metrics.Counter,
		"Download/install progress notifications by tenant, notification point and status.")
	reg.Describe("rsp42_acr_requests_total", metrics.Counter,
		"ES2+ HandleAcrRequest confirmations by tenant and outcome (allowed|refused|error).")
	reg.Describe("rsp42_euicc_v3_capable_total", metrics.Counter,
		"eUICCs advertising a SAIP version at or above the V3 baseline (N11).")
	reg.Describe("rsp42_profile_version_not_supported_total", metrics.Counter,
		"Downloads refused because no registered template matched the eUICC's SAIP versions (N12).")
}
