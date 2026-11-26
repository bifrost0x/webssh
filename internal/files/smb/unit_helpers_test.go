package smb

import (
	"net/netip"
	"strconv"

	"github.com/hirochachacha/go-smb2/v2/x/protocol"

	"github.com/bifrost0x/webssh/internal/store"
)

func mustAddrPort(ip string, port int) netip.AddrPort {
	return netip.MustParseAddrPort(ip + ":" + strconv.Itoa(port))
}

type storeTx = store.Tx

var (
	responseError = protocol.ResponseError{Code: statusObjectNameCollision}
	ioTimeout     = protocol.ResponseError{Code: statusIOTimeout}
)
