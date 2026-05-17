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
#pragma once

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
    SendWsUpgrade,
    WaitWsResponse,
    Connected
  } state_{State::SendWsUpgrade};

  string ws_key_;  // base64-encoded 16-byte random Sec-WebSocket-Key

  void send_ws_upgrade();
  Status wait_ws_response();

  Status loop_impl() final;

  // Parse the endpoint URL stored in username_ into host + path.
  static void parse_endpoint(const string &url, string *host, string *path);
};

}  // namespace td
// === TYPE3-PROXY END ===
