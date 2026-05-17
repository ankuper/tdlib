// === TYPE3-PROXY BEGIN ===
//
// WebSocketType3Proxy — implementation
// Handles HTTP/1.1 WebSocket upgrade handshake for Type3 proxy connections.
//
#include "td/net/WebSocketType3Proxy.h"

#include "td/utils/base64.h"
#include "td/utils/common.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/Random.h"
#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"

namespace td {

// ---------------------------------------------------------------------------
// parse_endpoint — split "wss://host:port/path" → host, path
// ---------------------------------------------------------------------------
void WebSocketType3Proxy::parse_endpoint(const string &url, string *host, string *path) {
  // Strip scheme prefix: "wss://" or "ws://"
  Slice u(url);
  if (u.substr(0, 6) == "wss://") {
    u = u.substr(6);
  } else if (u.substr(0, 5) == "ws://") {
    u = u.substr(5);
  }

  // host:port is up to the first '/'
  auto slash_pos = u.find('/');
  if (slash_pos == Slice::npos) {
    *host = u.str();
    *path = "/";
  } else {
    // Strip port from host if present for the Host header
    Slice host_part = u.substr(0, slash_pos);
    auto colon_pos = host_part.rfind(':');
    if (colon_pos != Slice::npos) {
      *host = host_part.substr(0, colon_pos).str();
    } else {
      *host = host_part.str();
    }
    *path = u.substr(slash_pos).str();
  }
}

// ---------------------------------------------------------------------------
// send_ws_upgrade — emit HTTP/1.1 GET with WebSocket upgrade headers
// ---------------------------------------------------------------------------
void WebSocketType3Proxy::send_ws_upgrade() {
  VLOG(proxy) << "WebSocketType3Proxy: send WS upgrade";
  CHECK(state_ == State::SendWsUpgrade);
  state_ = State::WaitWsResponse;

  // Endpoint URL is stored in username_ (see constructor)
  const string &endpoint = username_;
  string host, path;
  parse_endpoint(endpoint, &host, &path);

  // Generate 16-byte random nonce, base64-encode it → Sec-WebSocket-Key
  uint8 nonce[16];
  Random::secure_bytes(MutableSlice(reinterpret_cast<char *>(nonce), 16));
  ws_key_ = base64_encode(Slice(reinterpret_cast<const char *>(nonce), 16));

  fd_.output_buffer().append(PSLICE() << "GET " << path << " HTTP/1.1\r\n"
                                      << "Host: " << host << "\r\n"
                                      << "Connection: Upgrade\r\n"
                                      << "Upgrade: websocket\r\n"
                                      << "Sec-WebSocket-Version: 13\r\n"
                                      << "Sec-WebSocket-Key: " << ws_key_ << "\r\n"
                                      << "\r\n");
}

// ---------------------------------------------------------------------------
// wait_ws_response — parse HTTP 101 and validate Sec-WebSocket-Accept
// ---------------------------------------------------------------------------
Status WebSocketType3Proxy::wait_ws_response() {
  CHECK(state_ == State::WaitWsResponse);
  auto &buf = fd_.input_buffer();
  VLOG(proxy) << "WebSocketType3Proxy: receive WS response, size=" << buf.size();

  // Need at least "HTTP/1.1 101 " (12 bytes)
  if (buf.size() < 12) {
    return Status::OK();
  }

  // Peek without consuming — we need to find the end of headers (\r\n\r\n)
  auto it = buf.clone();
  string received;
  // Read up to 4096 bytes looking for end-of-headers
  const size_t MAX_HEADER_SIZE = 4096;
  size_t to_read = std::min(buf.size(), MAX_HEADER_SIZE);
  received.resize(to_read);
  it.advance(to_read, MutableSlice(&received[0], to_read));

  // Find \r\n\r\n
  auto eoh = received.find("\r\n\r\n");
  if (eoh == string::npos) {
    if (buf.size() >= MAX_HEADER_SIZE) {
      return Status::Error("WebSocketType3Proxy: HTTP headers too long");
    }
    return Status::OK();  // wait for more data
  }
  string headers = received.substr(0, eoh + 4);

  // Validate status line
  if (headers.substr(0, 12) != "HTTP/1.1 101") {
    return Status::Error(PSLICE() << "WebSocketType3Proxy: expected 101, got: "
                                  << headers.substr(0, std::min<size_t>(headers.size(), 40)));
  }

  // Validate Sec-WebSocket-Accept per RFC 6455 §4.2.2
  // Expected = base64(SHA1(ws_key_ + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
  string expected_accept =
      base64_encode(sha1(PSLICE() << ws_key_ << "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));

  // Search for the Sec-WebSocket-Accept header
  bool accept_ok = false;
  size_t pos = 0;
  while (pos < headers.size()) {
    size_t line_end = headers.find("\r\n", pos);
    string line = (line_end == string::npos) ? headers.substr(pos) : headers.substr(pos, line_end - pos);
    if (line.size() > 22) {
      string lower_line = line.substr(0, 22);
      for (auto &ch : lower_line) {
        ch = to_lower(ch);
      }
      if (lower_line == "sec-websocket-accept: ") {
        string value = line.substr(22);
        // Trim trailing whitespace
        while (!value.empty() && (value.back() == ' ' || value.back() == '\r')) {
          value.pop_back();
        }
        accept_ok = (value == expected_accept);
      }
    }
    if (line_end == string::npos) {
      break;
    }
    pos = line_end + 2;
  }

  if (!accept_ok) {
    VLOG(proxy) << "WebSocketType3Proxy: Sec-WebSocket-Accept mismatch (expected "
                << expected_accept << ")";
    // Per story: missing/wrong accept is a soft warning for now, not a fatal error,
    // because some enterprise TLS proxies strip custom headers.
    // We proceed — the transport will detect any corruption via MTProto auth.
  }

  // Consume headers from buffer
  buf.advance(eoh + 4);

  // Hand off to ConnectionCreator — WS is established.
  // Type3WebSocketTransport::init() will handle Session Header + obf2 init.
  state_ = State::Connected;
  stop();
  return Status::OK();
}

// ---------------------------------------------------------------------------
// loop_impl — called by TransparentProxy::loop() on I/O events
// ---------------------------------------------------------------------------
Status WebSocketType3Proxy::loop_impl() {
  switch (state_) {
    case State::SendWsUpgrade:
      send_ws_upgrade();
      break;
    case State::WaitWsResponse:
      TRY_STATUS(wait_ws_response());
      break;
    case State::Connected:
      // Already stopped, shouldn't be called again
      break;
    default:
      UNREACHABLE();
  }
  return Status::OK();
}

}  // namespace td
// === TYPE3-PROXY END ===
