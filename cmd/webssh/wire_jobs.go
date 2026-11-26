package main

// jobsArea wires the area "jobs" (RT1): quotas, background jobs and cron (internal/quota, internal/jobs, internal/cron).
// RT1 fills in the hooks; no other package edits this file.
func jobsArea() extension {
	return extension{name: "jobs"}
}
