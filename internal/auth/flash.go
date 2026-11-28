package auth

import (
	"sync"
	"time"
)

// Flash is one message for the next page, with its category ("error",
// "success", "login_auth_source", "login_username").
type Flash struct {
	Category string
	Message  string
}

// Bounds of the flash store: messages wait at most flashTTL, a browser has
// at most maxFlashes, the store at most maxFlashBrowsers. A full store
// drops its oldest entry for a new browser, so requests without a cookie
// cannot keep the messages of other browsers out.
const (
	flashTTL         = 10 * time.Minute
	maxFlashes       = 8
	maxFlashBrowsers = 4096
)

type flashEntry struct {
	at       time.Time
	messages []Flash
}

// flashes keeps messages across one redirect, keyed by the browser
// binding. Python kept them in the signed session cookie; Go keeps them in
// memory, so a cookie cannot inject text into a page.
type flashes struct {
	mu sync.Mutex
	m  map[string]*flashEntry
}

func (f *flashes) add(now time.Time, binding string, msgs ...Flash) {
	if binding == "" || len(msgs) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]*flashEntry{}
	}
	e := f.m[binding]
	if e == nil {
		if len(f.m) >= maxFlashBrowsers {
			f.expire(now)
			if len(f.m) >= maxFlashBrowsers {
				f.dropOldest()
			}
		}
		e = &flashEntry{}
		f.m[binding] = e
	}
	e.at = now
	e.messages = append(e.messages, msgs...)
	if n := len(e.messages); n > maxFlashes {
		e.messages = e.messages[n-maxFlashes:]
	}
}

func (f *flashes) dropOldest() {
	var oldest string
	var at time.Time
	for k, e := range f.m {
		if oldest == "" || e.at.Before(at) {
			oldest, at = k, e.at
		}
	}
	delete(f.m, oldest)
}

func (f *flashes) expire(now time.Time) {
	for k, e := range f.m {
		if now.Sub(e.at) > flashTTL {
			delete(f.m, k)
		}
	}
}

// take returns and removes the messages of a binding.
func (f *flashes) take(now time.Time, binding string) []Flash {
	if binding == "" {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.m[binding]
	delete(f.m, binding)
	if e == nil || now.Sub(e.at) > flashTTL {
		return nil
	}
	return e.messages
}
