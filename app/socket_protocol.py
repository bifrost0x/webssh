"""Shared constants for the browser-to-server Socket.IO wire contract."""


# This value is intentionally independent of the application release version.
# Increment it only when an incompatible Socket.IO payload contract is shipped.
SOCKET_WIRE_REVISION = 1
SOCKET_PROTOCOL_MISMATCH_EVENT = 'socket_protocol_mismatch'
