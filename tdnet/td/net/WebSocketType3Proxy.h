// === TYPE3-PROXY BEGIN ===
//
// WebSocketType3Proxy — handshake actor for Type3 WebSocket proxy connections.
//
// Extends TransparentProxy and handles HTTP/1.1 WebSocket upgrade.
// After 101 Switching Protocols the socket is handed back via
// TransparentProxy::Callback::set_result(BufferedFd).
//
// Constructor field mapping (re-uses TransparentProxy protected fields):
//   username_ = full endpoint URL, e.g. "wss://host:443/ws/path"
//   password_ = "" (unused)
//
// TLS support (AC #1-#7, Story 10-7):
//   When the endpoint starts with "wss://", a real OpenSSL TLS handshake
//   is performed transparently via TDLib's SslStream ByteFlow pipeline.
//   The pipeline mirrors HttpConnectionBase:
//     Read:  fd_.input_buffer → read_source_ >> ssl_stream_.read_byte_flow() >> read_sink_
//     Write: app_write_buf_   → write_source_ >> ssl_stream_.write_byte_flow() >> write_sink_ → fd_.output_buffer
//   SSL manages the handshake internally; application data flows once it completes.
//
#pragma once

#include "td/net/TlsPipeline.h"
#include "td/net/TransparentProxy.h"

#include "td/utils/Status.h"

namespace td {

class WebSocketType3Proxy final : public TransparentProxy {
 public:
  // socket_fd     : pre-opened TCP socket to the proxy endpoint IP
  // ip_address    : resolved IP of the MTProto DC (passed for actor context)
  // endpoint      : full WSS URL, e.g. "wss://host:443/ws/path"  (stored in username_)
  // callback      : TransparentProxy::Callback
  // parent        : parent actor
  WebSocketType3Proxy(SocketFd socket_fd, IPAddress ip_address, string endpoint,
                      unique_ptr<Callback> callback, ActorShared<> parent)
      : TransparentProxy(std::move(socket_fd), std::move(ip_address), std::move(endpoint), "",
                         std::move(callback), std::move(parent)) {
  }

 private:
  enum class State {
    // === TYPE3-PROXY BEGIN ===
    Init,            // First loop_impl() call: detect wss:// and set up TLS pipeline
    TlsHandshake,   // Pump TLS until SSL handshake completes (wss:// only)
    // === TYPE3-PROXY END ===
    SendWsUpgrade,
    WaitWsResponse,
    Connected
  } state_{State::Init};

  string ws_key_;  // base64-encoded 16-byte random Sec-WebSocket-Key

  // === TYPE3-PROXY BEGIN ===
  bool use_tls_{false};   // true when endpoint uses wss://

  // TLS ByteFlow pipeline — heap-allocated so internal ByteFlow pointers
  // remain stable when ownership is transferred to RawConnectionDefault.
  // Created in do_init() for wss:// connections; nullptr for ws://.
  unique_ptr<TlsPipeline> tls_pipeline_;
  // === TYPE3-PROXY END ===

  void send_ws_upgrade();
  Status wait_ws_response();

  // === TYPE3-PROXY BEGIN ===
  Status do_init();           // State::Init — detect wss://, create SslStream + wire ByteFlow pipeline
  Status wait_tls_handshake();// State::TlsHandshake — pump TLS until is_init_finished()
  void pump_tls();            // Pump read_source_ and write_source_ to drive SSL I/O
  void tear_down() override;  // Override to pass TLS pipeline via set_result
  // === TYPE3-PROXY END ===

  Status loop_impl() final;

  // Parse the endpoint URL stored in username_ into host:port and path.
  static void parse_endpoint(const string &url, string *host, string *path);

  // === TYPE3-PROXY BEGIN ===
  // Extract hostname only (no port) for TLS SNI.
  static string extract_sni_host(const string &url);
  // === TYPE3-PROXY END ===
};

}  // namespace td
// === TYPE3-PROXY END ===
