package quota

import "testing"

func TestLimitsCheck(t *testing.T) {
	t.Parallel()
	for _, kind := range Kinds() {
		if err := DefaultLimits[kind].Check(kind); err != nil {
			t.Errorf("default %s: %v", kind, err)
		}
	}
	bad := []struct {
		kind string
		l    Limit
	}{
		{Transfer, Limit{2, 2}}, {SSHSession, Limit{5, 6}}, {TempBytes, Limit{0, 0}}, {BackgroundJob, Limit{1, 2}},
	}
	for _, b := range bad {
		if b.l.Check(b.kind) == nil {
			t.Errorf("%s %+v accepted", b.kind, b.l)
		}
	}
	if err := (Limit{1, 1}).Check(BackgroundJob); err != nil {
		t.Errorf("background_job may give one user every slot: %v", err)
	}
}

func TestWithinStorage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		size, stored, limit int64
		want                bool
	}{
		{10, -1, 10, true}, {11, -1, 10, false}, {12, 12, 10, true}, {11, 12, 10, true}, {13, 12, 10, false},
	}
	for _, c := range cases {
		if got := WithinStorage(c.size, c.stored, c.limit); got != c.want {
			t.Errorf("WithinStorage(%d, %d, %d) = %v", c.size, c.stored, c.limit, got)
		}
	}
}
