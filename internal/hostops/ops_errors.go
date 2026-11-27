package hostops

// opError is an OperationError of the Python release: a code the page
// knows, with the HTTP status of server_operations_routes.
type opError struct{ code string }

func (e *opError) Error() string { return "hostops: server operation " + e.code }

func opErr(code string) error { return &opError{code: code} }
