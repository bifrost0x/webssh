package sftp

import "time"

// Defaults and bounds of the SFTP limits. The names and values are those
// of the Python release (config.py).
const (
	DefaultMaxPacketBytes   = 1 << 20 // SFTP_MAX_PACKET_BYTES
	MinMaxPacketBytes       = 64 << 10
	MaxMaxPacketBytes       = 4 << 20
	DefaultMaxHandleBytes   = 16 << 10 // SFTP_MAX_HANDLE_BYTES
	DefaultMaxNameBytes     = 4096     // REMOTE_FILENAME_MAX_BYTES
	DefaultMaxMetadataBytes = 4 << 20  // REMOTE_LISTING_MAX_METADATA_BYTES
	DefaultOperationTimeout = 30 * time.Second
	DefaultMutationTimeout  = 10 * time.Second
	DefaultChunkBytes       = 64 << 10
	DefaultPrefetch         = 32
)

// Options configure a Backend. Zero fields take the defaults.
type Options struct {
	// MaxPacketBytes bounds every packet the server sends.
	MaxPacketBytes int
	// MaxHandleBytes bounds a file or directory handle.
	MaxHandleBytes int
	// MaxNameBytes bounds a file name, a long name and an extension name
	// or value.
	MaxNameBytes int
	// MaxMetadataBytes bounds the names and metadata of one listing or
	// tree operation.
	MaxMetadataBytes int
	// MaxMembers bounds the entries of one listing or tree operation
	// (MAX_TRANSFER_MEMBERS).
	MaxMembers int
	// OperationTimeout is SFTP_OPERATION_TIMEOUT: a request without a
	// reply for that long closes the channel, and it bounds each read.
	OperationTimeout time.Duration
	// MutationTimeout bounds a mutation (the 10 seconds of the Python
	// release).
	MutationTimeout time.Duration
	// ChmodEnabled is the admin switch sftp_chmod_enabled.
	ChmodEnabled bool
	// ChunkBytes is the size of one read or write request; the server's
	// limits@openssh.com lowers it.
	ChunkBytes int
	// Prefetch is the number of read requests a download keeps in flight,
	// and of write requests an upload keeps in flight.
	Prefetch int
}

func (o Options) withDefaults() Options {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&o.MaxPacketBytes, DefaultMaxPacketBytes)
	o.MaxPacketBytes = min(max(o.MaxPacketBytes, MinMaxPacketBytes), MaxMaxPacketBytes)
	def(&o.MaxHandleBytes, DefaultMaxHandleBytes)
	def(&o.MaxNameBytes, DefaultMaxNameBytes)
	def(&o.MaxMetadataBytes, DefaultMaxMetadataBytes)
	def(&o.ChunkBytes, DefaultChunkBytes)
	def(&o.Prefetch, DefaultPrefetch)
	// A data reply is the chunk plus 13 bytes of header; it must fit.
	o.ChunkBytes = min(o.ChunkBytes, o.MaxPacketBytes-1024)
	o.Prefetch = min(o.Prefetch, 256)
	if o.OperationTimeout <= 0 {
		o.OperationTimeout = DefaultOperationTimeout
	}
	if o.MutationTimeout <= 0 {
		o.MutationTimeout = DefaultMutationTimeout
	}
	return o
}
