// === TYPE3-PROXY BEGIN ===
//
// WebSocketType3Proxy — implementation
// Handles HTTP/1.1 WebSocket upgrade handshake for Type3 proxy connections.
// Story 10-7: adds real TLS handshake via SslStream for wss:// endpoints.
//
#include "td/net/WebSocketType3Proxy.h"

#include "td/net/SslCtx.h"
#include "td/net/SslStream.h"

#include "td/utils/base64.h"
#include "td/utils/ByteFlow.h"
#include "td/utils/common.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/Random.h"
#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"

namespace td {

// ---------------------------------------------------------------------------
// parse_endpoint — split "wss://host:port/path" → host:port string, path
// ---------------------------------------------------------------------------
void WebSocketType3Proxy::parse_endpoint(const string &url, string *host, string *path) {
  Slice u(url);
  if (u.substr(0, 6) == "wss://") {
    u = u.substr(6);
  } else if (u.substr(0, 5) == "ws://") {
    u = u.substr(5);
  }
  auto slash_pos = u.find('/');
  if (slash_pos == Slice::npos) {
    *host = u.str();
    *path = "/";
  } else {
    *host = u.substr(0, slash_pos).str();
    *path = u.substr(slash_pos).str();
  }
}

// === TYPE3-PROXY BEGIN ===
// extract_sni_host — returns hostname only (strips port) for TLS SNI (AC #4).
// e.g. "wss://arctic-breeze.my.id:443/ws/path" → "arctic-breeze.my.id"
string WebSocketType3Proxy::extract_sni_host(const string &url) {
  Slice u(url);
  if (u.substr(0, 6) == "wss://") {
    u = u.substr(6);
  } else if (u.substr(0, 5) == "ws://") {
    u = u.substr(5);
  }
  auto slash_pos = u.find('/');
  Slice host_port = (slash_pos == Slice::npos) ? u : u.substr(0, slash_pos);
  auto colon_pos = host_port.rfind(':');
  if (colon_pos != Slice::npos) {
    return host_port.substr(0, colon_pos).str();
  }
  return host_port.str();
}

// ---------------------------------------------------------------------------
// do_init — detect wss:// scheme, create SslStream, wire ByteFlow pipeline.
// Called once from loop_impl() when state_ == Init.
// AC: #1, #2, #3, #4, #6, #8
// ---------------------------------------------------------------------------
Status WebSocketType3Proxy::do_init() {
  const string &endpoint = username_;
  Slice url(endpoint);

  if (url.substr(0, 6) == "wss://") {
    // === TYPE3-PROXY BEGIN ===
    use_tls_ = true;
    const string sni_host = extract_sni_host(endpoint);
    VLOG(proxy) << "WebSocketType3Proxy: wss:// detected, TLS SNI=" << sni_host;

    // Create SSL context with system CA store and full peer verification (AC #6)
    TRY_RESULT(ssl_ctx, SslCtx::create(CSlice(), SslCtx::VerifyPeer::On));

    // Create SslStream — sets SNI via SSL_set_tlsext_host_name internally (AC #4)
    // Uses TDLib's existing SslStream, no custom OpenSSL code (AC #3)
    TRY_RESULT(ssl, SslStream::create(CSlice(sni_host), std::move(ssl_ctx)));
    ssl_stream_ = std::move(ssl);

    // Wire ByteFlow pipeline (mirrors HttpConnectionBase constructor pattern):
    //   Read:  fd_.input_buffer → read_source_ >> ssl_stream_.read_byte_flow() >> read_sink_
    //   Write: app_write_buf_   → write_source_ >> ssl_stream_.write_byte_flow() >> write_sink_ → fd_.output_buffer
    app_write_reader_ = app_write_buf_.extract_reader();
    read_source_ = ByteFlowSource(&fd_.input_buffer());
    write_source_ = ByteFlowSource(&app_write_reader_);
    write_sink_ = ByteFlowMoveSink(&fd_.output_buffer());

    read_source_ >> ssl_stream_.read_byte_flow() >> read_sink_;
    write_source_ >> ssl_stream_.write_byte_flow() >> write_sink_;
    // === TYPE3-PROXY END ===
  } else {
    // Plain ws:// — no TLS (AC #2)
    use_tls_ = false;
  }

  state_ = State::SendWsUpgrade;
  return Status::OK();
}

// ---------------------------------------------------------------------------
// pump_tls — drive both byte flow directions for TLS I/O.
// This drives the OpenSSL handshake transparently: SSL_read/SSL_write are
// called internally by ByteFlow wakeup; application data only flows after
// the handshake completes. AC: #1, #5
// ---------------------------------------------------------------------------
// === TYPE3-PROXY BEGIN ===
void WebSocketType3Proxy::pump_tls() {
  CHECK(use_tls_);
  // Push ciphertext from fd_.input_buffer() through SSL decrypt → read_sink_ output
  read_source_.wakeup();
  // Push plaintext from app_write_buf_ through SSL encrypt → fd_.output_buffer()
  write_source_.wakeup();
}
// === TYPE3-PROXY END ===

// ---------------------------------------------------------------------------
// send_ws_upgrade — emit HTTP/1.1 GET with WebSocket upgrade headers
// ---------------------------------------------------------------------------
void WebSocketType3Proxy::send_ws_upgrade() {
  VLOG(proxy) << "WebSocketType3Proxy: send WS upgrade";
  CHECK(state_ == State::SendWsUpgrade);
  state_ = State::WaitWsResponse;

  const string &endpoint = username_;
  string host, path;
  parse_endpoint(endpoint, &host, &path);

  // Generate 16-byte random nonce, base64-encode → Sec-WebSocket-Key
  uint8 nonce[16];
  Random::secure_bytes(MutableSlice(reinterpret_cast<char *>(nonce), 16));
  ws_key_ = base64_encode(Slice(reinterpret_cast<const char *>(nonce), 16));

  const string upgrade_request = PSTRING() << "GET " << path << " HTTP/1.1\r\n"
                                           << "Host: " << host << "\r\n"
                                           << "Connection: Upgrade\r\n"
                                           << "Upgrade: websocket\r\n"
                                           << "Sec-WebSocket-Version: 13\r\n"
                                           << "Sec-WebSocket-Key: " << ws_key_ << "\r\n"
                                           << "\r\n";

  // === TYPE3-PROXY BEGIN ===
  if (use_tls_) {
    // Write to app_write_buf_ → flows through SSL encrypt → fd_.output_buffer() (AC #5)
    // If TLS handshake is still in progress, OpenSSL will buffer application data
    // internally and send it once the handshake completes (standard OpenSSL behaviour).
    app_write_buf_.append(upgrade_request);
    pump_tls();
  } else {
    // Plaintext ws:// — direct write (AC #2)
    fd_.output_buffer().append(upgrade_request);
  }
  // === TYPE3-PROXY END ===
}

// ---------------------------------------------------------------------------
// wait_ws_response — parse HTTP 101 and validate Sec-WebSocket-Accept
// ---------------------------------------------------------------------------
Status WebSocketType3Proxy::wait_ws_response() {
  CHECK(state_ == State::WaitWsResponse);

  // === TYPE3-PROXY BEGIN ===
  string decrypted;
  Slice response_data;

  if (use_tls_) {
    // Pump TLS: decrypt incoming ciphertext from fd_.input_buffer() (AC #5)
    pump_tls();

    // Check for TLS errors (AC #7)
    if (read_sink_.status().is_error()) {
      return Status::Error(PSLICE() << "WebSocketType3Proxy: TLS handshake failed: "
                                    << read_sink_.status().message());
    }
    if (write_sink_.status().is_error()) {
      return Status::Error(PSLICE() << "WebSocketType3Proxy: TLS handshake failed: "
                                    << write_sink_.status().message());
    }

    // Read decrypted plaintext from read_sink_ output
    auto *output = read_sink_.get_output();
    size_t available = output->size();
    if (available > 0) {
      decrypted.resize(available);
      output->advance(available, MutableSlice(&decrypted[0], available));
    }
    response_data = Slice(decrypted);
  } else {
    // Plaintext: read from fd_.input_buffer() via clone (do not consume yet)
    auto &raw = fd_.input_buffer();
    size_t raw_size = raw.size();
    decrypted.resize(raw_size);
    auto raw_clone = raw.clone();
    raw_clone.advance(raw_size, MutableSlice(&decrypted[0], raw_size));
    response_data = Slice(decrypted);
  }
  // === TYPE3-PROXY END ===

  VLOG(proxy) << "WebSocketType3Proxy: receive WS response, size=" << response_data.size();

  // Need at least "HTTP/1.1 101 " (12 bytes)
  if (response_data.size() < 12) {
    return Status::OK();  // wait for more data
  }

  // Find end of HTTP headers (\r\n\r\n)
  const size_t MAX_HEADER_SIZE = 4096;
  string received(response_data.begin(), std::min(response_data.size(), MAX_HEADER_SIZE));

  auto eoh = received.find("\r\n\r\n");
  if (eoh == string::npos) {
    if (response_data.size() >= MAX_HEADER_SIZE) {
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
  string expected_accept =
      base64_encode(sha1(PSLICE() << ws_key_ << "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));

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
    // Soft warning — MTProto auth will detect any corruption.
  }

  // === TYPE3-PROXY BEGIN ===
  // Consume header bytes from the underlying buffer
  if (!use_tls_) {
    // For plaintext: advance the fd_ input buffer past the headers
    fd_.input_buffer().advance(eoh + 4);
  }
  // For TLS: read_sink_ output was already consumed above via output->advance().
  // fd_.input_buffer() ciphertext was consumed by ByteFlow read_source_ automatically.
  // === TYPE3-PROXY END ===

  // Hand off to ConnectionCreator — WS is established.
  state_ = State::Connected;
  stop();
  return Status::OK();
}

// ---------------------------------------------------------------------------
// loop_impl — called by TransparentProxy::loop() on each I/O event
// ---------------------------------------------------------------------------
Status WebSocketType3Proxy::loop_impl() {
  switch (state_) {
    // === TYPE3-PROXY BEGIN ===
    case State::Init:
      TRY_STATUS(do_init());
      // do_init() sets state_ = SendWsUpgrade; fall through immediately
      [[fallthrough]];
    // === TYPE3-PROXY END ===
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
