// === TYPE3-PROXY BEGIN ===
//
// RawConnectionType3 — mtproto::RawConnection backed by the canonical
// libteleproto3 `t3_client_*` transport API.
//
// This is the ONLY place TDLib touches the Type3 transport. The whole Type3
// protocol stack (TLS + obfs2 init + AES-256-CTR + HTTP-chunk framing) lives
// inside libteleproto3 and is consumed here through the high-level handle:
//
//   t3_client_create  -> t3_client_get_fd  -> t3_client_pump
//   t3_client_read / t3_client_write       -> t3_client_destroy
//
// It mirrors the shipped reference integration in Telegram-Android
// (ConnectionSocket.cpp, the proxyAuthState==20/21 state machine): the C
// library owns the fd + TLS + framing; the host just polls the fd, pumps the
// state machine to READY, then reads/writes *bare MTProto packets*.
//
// There is NO client-side re-implementation of the Type3 wire format here.
// (The old Type3HttpStreamTransport / Type3WebSocketTransport / Type3Transport
// IStreamTransport re-implementations and the WebSocketType3Proxy /
// HttpStreamType3Proxy TLS actors have been removed.)
//
// HTTP-stream ONLY (https:// endpoint). WebSocket transport is dead.
//
#pragma once

#include "td/mtproto/RawConnection.h"

#include "td/utils/common.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"

namespace td {
namespace mtproto {

// Build a RawConnection that drives libteleproto3's t3_client_* transport.
//
//   endpoint : full https URL, e.g. "https://host:443/api/v1/data"
//   secret   : 16-byte Type3 proxy key (already stripped of the 0xff prefix
//              and the domain suffix by the caller)
//   dc_id    : signed Telegram DC id (negative = media)
//
// On success returns a RawConnection already in CONNECTING state with its fd
// registered for polling. On failure returns an error Status (no fd leaked).
Result<unique_ptr<RawConnection>> create_raw_connection_type3(
    IPAddress ip_address, string endpoint, UInt128 secret, int16 dc_id,
    unique_ptr<RawConnection::StatsCallback> stats_callback);

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
