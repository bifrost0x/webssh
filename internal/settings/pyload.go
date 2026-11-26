package settings

import (
	"encoding/json/jsontext"
	"errors"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// errPythonLoad marks a text json.loads of the Python release would
// refuse too: not UTF-8, or not JSON.
var errPythonLoad = errors.New("settings: not a JSON text")

// pythonLoad reads a JSON text the way the Python release does
// (pyjson.Load) and returns it compact, with unique names and valid
// UTF-8, so the strict helpers of this package apply. lone reports an
// escaped unpaired surrogate read as U+FFFD.
func pythonLoad(raw []byte) (v jsontext.Value, lone bool, err error) {
	v, rep, err := pyjson.Load(raw)
	if err != nil {
		return nil, false, errPythonLoad
	}
	return v, rep.LoneSurrogates, nil
}
