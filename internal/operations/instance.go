package operations

import (
	"cmp"
	"context"
	"slices"
	"time"
)

// maxDetails bounds the rows of each list of the details view, as the
// Python release does (limit=200).
const maxDetails = 200

// SocketStats is the capacity of the realtime endpoint: open connections,
// the limits and the refusals since the start (socket_capacity.snapshot).
type SocketStats struct {
	Active, Limit, PerUserLimit    int
	RejectedTotal, RejectedPerUser int
}

// Sockets reports the capacity of the realtime endpoint
// (internal/realtime).
type Sockets interface {
	SocketStats() SocketStats
}

// Usernames resolves account ids to user names for the views; an id
// without an account is missing from the result.
type Usernames interface {
	Usernames(ctx context.Context, ids []int64) (map[int64]string, error)
}

// Instance is the instance view of the administration (C-AOPS-05 to -09)
// and its three actions. A nil source shows an empty part.
type Instance struct {
	Connections Connections
	Sockets     Sockets
	Sessions    Sessions
	Transfers   Transfers
	Jobs        Jobs
	Quotas      Quotas
	Names       Usernames
	// Maintenance reports the maintenance mode; nil is never.
	Maintenance func() bool
	// Stopping reports that the server began to shut down and takes no
	// new background work; nil is never.
	Stopping func() bool
	Now      func() time.Time
}

func (in *Instance) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// Status is the body of GET /admin/api/operations: counts only, no
// names, ids or targets.
func (in *Instance) Status(ctx context.Context) (map[string]any, error) {
	sock := SocketStats{}
	if in.Sockets != nil {
		sock = in.Sockets.SocketStats()
	}
	active, users, tmux := in.sessionCounts()
	transfers := map[string]int{"pending": 0, "running": 0, "cancelling": 0}
	for _, t := range in.transfers() {
		if _, ok := transfers[t.State]; ok {
			transfers[t.State]++
		}
	}
	running := 0
	jobs := in.jobs()
	for _, j := range jobs {
		if j.Running {
			running++
		}
	}
	body := map[string]any{
		"sockets": map[string]int{
			"active": sock.Active, "limit": sock.Limit, "per_user_limit": sock.PerUserLimit,
			// There is no thread budget the realtime connections take
			// from (W-035), so nothing is held back for plain HTTP.
			"http_reserve":   0,
			"rejected_total": sock.RejectedTotal, "rejected_per_user": sock.RejectedPerUser,
		},
		"sessions": map[string]int{"active": active, "users": users, "tmux": tmux},
		"jobs": map[string]any{
			"workers": len(jobs), "running": running, "queued": 0, "cancelling": 0,
			"accepting_work": in.Stopping == nil || !in.Stopping(),
		},
		"transfers":   transfers,
		"maintenance": in.maintenance(),
	}
	if in.Quotas != nil {
		use, err := in.Quotas.Use(ctx)
		if err != nil {
			return nil, err
		}
		quotas := make([]map[string]any, 0, len(use))
		for _, q := range slices.SortedFunc(slices.Values(use), func(a, b QuotaUse) int { return cmp.Compare(a.Kind, b.Kind) }) {
			quotas = append(quotas, map[string]any{"kind": q.Kind, "used": q.Used, "limit": q.Limit})
		}
		body["quotas"] = quotas
	}
	return body, nil
}

func (in *Instance) maintenance() bool { return in.Maintenance != nil && in.Maintenance() }

func (in *Instance) sessions() []LiveSession {
	if in.Sessions == nil {
		return nil
	}
	_, items := in.Sessions.Live()
	return items
}

func (in *Instance) sessionCounts() (active, users, tmux int) {
	owners := map[int64]bool{}
	items := in.sessions()
	for _, s := range items {
		if s.UserID != 0 {
			owners[s.UserID] = true
		}
		if s.Tmux {
			tmux++
		}
	}
	return len(items), len(owners), tmux
}

func (in *Instance) transfers() []LiveTransfer {
	if in.Transfers == nil {
		return nil
	}
	return in.Transfers.Live()
}

func (in *Instance) jobs() []LiveJob {
	if in.Jobs == nil {
		return nil
	}
	return in.Jobs.Live()
}

func (in *Instance) connections() []LiveConnection {
	if in.Connections == nil {
		return nil
	}
	items := in.Connections.Live()
	slices.SortStableFunc(items, func(a, b LiveConnection) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return items
}

// list is one part of the details view.
type list struct {
	Total int              `json:"total"`
	Items []map[string]any `json:"items"`
}

// Details is the body of GET /admin/api/operations/details: references,
// owners and targets, at most 200 rows per list. Raw connection and
// session ids never leave the server.
func (in *Instance) Details(ctx context.Context) (map[string]any, error) {
	conns, sessions, transfers := in.connections(), in.sessions(), in.transfers()
	ids := map[int64]bool{}
	for _, c := range conns {
		ids[c.UserID] = true
	}
	for _, s := range sessions {
		ids[s.UserID] = true
	}
	for _, t := range transfers {
		ids[t.UserID] = true
	}
	names, err := in.names(ctx, ids)
	if err != nil {
		return nil, err
	}
	owner := func(id int64) any {
		if n, ok := names[id]; ok && id != 0 {
			return n
		}
		return nil
	}
	now := in.now()
	out := map[string]any{}
	cl := list{Total: len(conns), Items: []map[string]any{}}
	for _, c := range conns {
		// Python joins the connections with their accounts: one without an
		// account is not listed.
		if _, ok := names[c.UserID]; !ok {
			cl.Total--
			continue
		}
		if len(cl.Items) < maxDetails {
			cl.Items = append(cl.Items, map[string]any{"id": ConnectionRef(c.ID), "username": owner(c.UserID), "created_at": isoTime(c.CreatedAt)})
		}
	}
	out["connections"] = cl
	sl := list{Total: len(sessions), Items: []map[string]any{}}
	for _, s := range sessions[:min(len(sessions), maxDetails)] {
		sl.Items = append(sl.Items, map[string]any{"target": s.Target, "tmux": s.Tmux, "id": SessionRef(s.ID),
			"username": owner(s.UserID), "created_at": isoTime(s.CreatedAt)})
	}
	out["sessions"] = sl
	tl := list{Total: len(transfers), Items: []map[string]any{}}
	for _, t := range transfers[:min(len(transfers), maxDetails)] {
		tl.Items = append(tl.Items, map[string]any{"id": t.ID, "direction": t.Kind, "state": t.State,
			"age_seconds": age(now, t.CreatedAt), "username": owner(t.UserID)})
	}
	out["transfers"] = tl
	jobs := in.jobs()
	jl := list{Items: []map[string]any{}}
	for _, j := range jobs {
		if !j.Running {
			continue
		}
		jl.Total++
		if len(jl.Items) < maxDetails {
			jl.Items = append(jl.Items, map[string]any{"kind": jobKind(j.Name), "state": "running", "cancelling": false,
				"age_seconds": age(now, j.LastRun)})
		}
	}
	out["jobs"] = jl
	return out, nil
}

func (in *Instance) names(ctx context.Context, ids map[int64]bool) (map[int64]string, error) {
	delete(ids, 0)
	if in.Names == nil || len(ids) == 0 {
		return map[int64]string{}, nil
	}
	return in.Names.Usernames(ctx, slices.Sorted(func(yield func(int64) bool) {
		for id := range ids {
			if !yield(id) {
				return
			}
		}
	}))
}

// jobCategories are the bounded task kinds of the view; a job name never
// reaches the browser (runtime_lifecycle.admin_details).
var jobCategories = map[string]string{
	"ldap_session_revalidation": "maintenance", "transfer_cleanup": "maintenance", "backup_cleanup": "maintenance",
	"smb_source_cleanup": "maintenance", "platform_detection": "maintenance", "reachability": "maintenance",
	"automation_scheduler": "maintenance", "server_to_server_transfer": "transfer", "backup": "backup",
}

func jobKind(name string) string {
	if k, ok := jobCategories[name]; ok {
		return k
	}
	return "other"
}

func age(now, since time.Time) int64 {
	if since.IsZero() {
		return 0
	}
	return max(0, int64(now.Sub(since)/time.Second))
}

// isoTime is Python's naive UTC isoformat()+"Z" of the Python view; zero
// is null.
func isoTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "Z"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "Z"
}
