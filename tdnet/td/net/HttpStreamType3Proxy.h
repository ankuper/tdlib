// === TYPE3-PROXY BEGIN ===
//
// HttpStreamType3Proxy — TLS handshake actor for Type3 HTTP stream connections.
//
// Unlike WebSocketType3Proxy, this does NOT perform a WebSocket upgrade.
// After TLS handshake completes, the socket is handed off directly to
// RawConnection where Type3HttpStreamTransport sends POST+chunked headers.
//
// States: Init → TlsHandshake → Connected (no WS upgrade step)
//
#pragma once

#include "td/net/TlsPipeline.h"
#include "td/net/TransparentProxy.h"

#include "td/utils/Status.h"

namespace td {

class HttpStreamType3Proxy final : public TransparentProxy {
 public:
  // socket_fd     : pre-opened TCP socket to the proxy endpoint IP
  // ip_address    : resolved IP of the MTProto DC (passed for actor context)
  // endpoint      : full HTTPS URL, e.g. "https://host:443/api/v1/data" (stored in username_)
  // callback      : TransparentProxy::Callback
  // parent        : parent actor
  HttpStreamType3Proxy(SocketFd socket_fd, IPAddress ip_address, string endpoint,
                       unique_ptr<Callback> callback, ActorShared<> parent)
      : TransparentProxy(std::move(socket_fd), std::move(ip_address), std::move(endpoint), "",
                         std::move(callback), std::move(parent)) {
  }

 private:
  enum class State {
    Init,
    TlsHandshake,
    Connected
  } state_{State::Init};

  unique_ptr<TlsPipeline> tls_pipeline_;

  static string extract_sni_host(const string &url);

  Status do_init();
  Status wait_tls_handshake();

  void tear_down() override;
  Status loop_impl() final;
};

}  // namespace td
// === TYPE3-PROXY END ===
