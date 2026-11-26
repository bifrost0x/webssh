package ldapproto

import (
	"fmt"
	"unicode/utf8"
)

// Protocol operation tags (RFC 4511 section 4.2 onwards).
const (
	opBindRequest      = classApplication | constructedBit
	opBindResponse     = classApplication | constructedBit | 1
	opUnbindRequest    = classApplication | 2
	opSearchRequest    = classApplication | constructedBit | 3
	opSearchEntry      = classApplication | constructedBit | 4
	opSearchDone       = classApplication | constructedBit | 5
	opSearchReference  = classApplication | constructedBit | 19
	opExtendedRequest  = classApplication | constructedBit | 23
	opExtendedResponse = classApplication | constructedBit | 24
	opIntermediate     = classApplication | constructedBit | 25
)

const (
	oidStartTLS           = "1.3.6.1.4.1.1466.20037"
	oidNoticeOfDisconnect = "1.3.6.1.4.1.1466.20036"
	tagResultReferral     = classContext | constructedBit | 3
)

// Scope of a search request.
type Scope int

// Search scopes (RFC 4511 section 4.5.1.2).
const (
	ScopeBase     Scope = 0
	ScopeOne      Scope = 1
	ScopeSubtree  Scope = 2
	derefNever          = 0
	maxSearchSize       = 1 << 20
)

// Result is an LDAPResult (RFC 4511 section 4.1.9).
type Result struct {
	Code       ResultCode
	MatchedDN  string
	Diagnostic string
	Referrals  []string
}

// Entry is one search result entry with its attribute values.
type Entry struct {
	DN         string
	Attributes map[string][][]byte
}

// message is a decoded LDAPMessage envelope.
type message struct {
	id int64
	op element
}

func envelope(id int64, op []byte) []byte {
	var body []byte
	body = appendInt(body, tagInteger, id)
	body = append(body, op...)
	return appendTLV(nil, tagSequence, body)
}

func bindRequest(dn, password string) []byte {
	var body []byte
	body = appendInt(body, tagInteger, 3)
	body = appendOctetString(body, tagOctetString, dn)
	body = appendOctetString(body, classContext, password)
	return appendTLV(nil, opBindRequest, body)
}

func unbindRequest() []byte { return []byte{opUnbindRequest, 0x00} }

func startTLSRequest() []byte {
	return appendTLV(nil, opExtendedRequest, appendOctetString(nil, classContext, oidStartTLS))
}

// SearchRequest describes one search. Filter is a compiled filter from
// CompileFilter.
type SearchRequest struct {
	BaseDN     string
	Scope      Scope
	SizeLimit  int
	TimeLimit  int
	Filter     []byte
	Attributes []string
}

func (r SearchRequest) encode() []byte {
	var body []byte
	body = appendOctetString(body, tagOctetString, r.BaseDN)
	body = appendInt(body, tagEnumerated, int64(r.Scope))
	body = appendInt(body, tagEnumerated, derefNever)
	body = appendInt(body, tagInteger, int64(r.SizeLimit))
	body = appendInt(body, tagInteger, int64(r.TimeLimit))
	body = appendBool(body, tagBoolean, false)
	body = append(body, r.Filter...)
	var attrs []byte
	for _, a := range r.Attributes {
		attrs = appendOctetString(attrs, tagOctetString, a)
	}
	body = appendTLV(body, tagSequence, attrs)
	return appendTLV(nil, opSearchRequest, body)
}

func parseMessage(raw []byte) (message, error) {
	top, rest, err := parseElement(raw)
	if err != nil {
		return message{}, err
	}
	if len(rest) != 0 || top.tag != tagSequence {
		return message{}, fmt.Errorf("%w: envelope", ErrMalformed)
	}
	parts, err := top.children()
	if err != nil {
		return message{}, err
	}
	if len(parts) < 2 || len(parts) > 3 || parts[0].tag != tagInteger {
		return message{}, fmt.Errorf("%w: envelope members", ErrMalformed)
	}
	id, err := parts[0].integer()
	if err != nil || id < 0 {
		return message{}, fmt.Errorf("%w: message id", ErrMalformed)
	}
	return message{id: id, op: parts[1]}, nil
}

// parseResult decodes the LDAPResult components of a response operation
// and returns any members that follow them.
func parseResult(op element) (Result, []element, error) {
	parts, err := op.children()
	if err != nil {
		return Result{}, nil, err
	}
	if len(parts) < 3 || parts[0].tag != tagEnumerated ||
		parts[1].tag != tagOctetString || parts[2].tag != tagOctetString {
		return Result{}, nil, fmt.Errorf("%w: result", ErrMalformed)
	}
	code, err := parts[0].integer()
	if err != nil {
		return Result{}, nil, err
	}
	res := Result{
		Code:       ResultCode(code),
		MatchedDN:  string(parts[1].content),
		Diagnostic: string(parts[2].content),
	}
	rest := parts[3:]
	if len(rest) > 0 && rest[0].tag == tagResultReferral {
		res.Referrals, err = parseURIs(rest[0])
		if err != nil {
			return Result{}, nil, err
		}
		rest = rest[1:]
	}
	return res, rest, nil
}

func parseURIs(e element) ([]string, error) {
	items, err := e.children()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item.tag != tagOctetString || !utf8.Valid(item.content) {
			return nil, fmt.Errorf("%w: referral URI", ErrMalformed)
		}
		out = append(out, string(item.content))
	}
	return out, nil
}

func parseEntry(op element) (Entry, error) {
	parts, err := op.children()
	if err != nil {
		return Entry{}, err
	}
	if len(parts) != 2 || parts[0].tag != tagOctetString || parts[1].tag != tagSequence {
		return Entry{}, fmt.Errorf("%w: search entry", ErrMalformed)
	}
	if !utf8.Valid(parts[0].content) {
		return Entry{}, fmt.Errorf("%w: entry DN is not UTF-8", ErrMalformed)
	}
	attrs, err := parts[1].children()
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{DN: string(parts[0].content), Attributes: make(map[string][][]byte, len(attrs))}
	for _, attr := range attrs {
		pair, err := attr.children()
		if err != nil || attr.tag != tagSequence || len(pair) != 2 ||
			pair[0].tag != tagOctetString || pair[1].tag != tagSet {
			return Entry{}, fmt.Errorf("%w: partial attribute", ErrMalformed)
		}
		vals, err := pair[1].children()
		if err != nil {
			return Entry{}, err
		}
		values := make([][]byte, 0, len(vals))
		for _, v := range vals {
			if v.tag != tagOctetString {
				return Entry{}, fmt.Errorf("%w: attribute value", ErrMalformed)
			}
			values = append(values, v.content)
		}
		name := string(pair[0].content)
		entry.Attributes[name] = append(entry.Attributes[name], values...)
	}
	return entry, nil
}
