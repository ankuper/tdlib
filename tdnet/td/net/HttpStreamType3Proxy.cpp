// === TYPE3-PROXY BEGIN ===
//
// HttpStreamType3Proxy — implementation
// TLS-only handshake for Type3 HTTP stream proxy connections.
// No WebSocket upgrade — Type3HttpStreamTransport handles POST+chunked framing.
//
#include "td/net/HttpStreamType3Proxy.h"

#include "td/net/SslCtx.h"
#include "td/net/SslStream.h"
#include "td/net/TlsPipeline.h"

#include "td/utils/logging.h"
#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"

namespace td {

// ---------------------------------------------------------------------------
// extract_sni_host — "https://arctic-breeze.my.id:443/path" → "arctic-breeze.my.id"
// ---------------------------------------------------------------------------
string HttpStreamType3Proxy::extract_sni_host(const string &url) {
  Slice u(url);
  if (u.substr(0, 8) == "https://") {
    u = u.substr(8);
  } else if (u.substr(0, 7) == "http://") {
    u = u.substr(7);
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
// do_init — create TLS pipeline for https:// endpoint
// ---------------------------------------------------------------------------
Status HttpStreamType3Proxy::do_init() {
  const string &endpoint = username_;
  Slice url(endpoint);

  if (url.substr(0, 8) == "https://") {
    const string sni_host = extract_sni_host(endpoint);
    VLOG(proxy) << "HttpStreamType3Proxy: TLS SNI=" << sni_host;

    TRY_RESULT(ssl_ctx, SslCtx::create(CSlice(), SslCtx::VerifyPeer::On));
    TRY_RESULT(ssl, SslStream::create(CSlice(sni_host), std::move(ssl_ctx)));

    tls_pipeline_ = make_unique<TlsPipeline>();
    tls_pipeline_->ssl_stream = std::move(ssl);
    tls_pipeline_->wire(&fd_.input_buffer(), &fd_.output_buffer());
    tls_pipeline_->pump();

    state_ = State::TlsHandshake;
  } else {
    // http:// — no TLS, go straight to connected
    VLOG(proxy) << "HttpStreamType3Proxy: plain HTTP (no TLS)";
    state_ = State::Connected;
    stop();
  }

  return Status::OK();
}

// ---------------------------------------------------------------------------
// wait_tls_handshake — pump TLS until handshake completes
// ---------------------------------------------------------------------------
Status HttpStreamType3Proxy::wait_tls_handshake() {
  CHECK(state_ == State::TlsHandshake);
  CHECK(tls_pipeline_);

  tls_pipeline_->pump();

  if (tls_pipeline_->read_sink.status().is_error()) {
    return Status::Error(PSLICE() << "HttpStreamType3Proxy: TLS handshake failed: "
                                  << tls_pipeline_->read_sink.status().message());
  }
  if (tls_pipeline_->write_sink.status().is_error()) {
    return Status::Error(PSLICE() << "HttpStreamType3Proxy: TLS handshake failed: "
                                  << tls_pipeline_->write_sink.status().message());
  }

  if (tls_pipeline_->ssl_stream.is_init_finished()) {
    VLOG(proxy) << "HttpStreamType3Proxy: TLS handshake complete";
    state_ = State::Connected;
    stop();
  }
  return Status::OK();
}

// ---------------------------------------------------------------------------
// tear_down — pass TLS pipeline to RawConnection
// ---------------------------------------------------------------------------
void HttpStreamType3Proxy::tear_down() {
  if (state_ == State::Connected && tls_pipeline_ && callback_) {
    VLOG(proxy) << "HttpStreamType3Proxy: handing off TLS pipeline to RawConnection";
    Scheduler::unsubscribe(fd_.get_poll_info().get_pollable_fd_ref());
    callback_->set_result(std::move(fd_), std::move(tls_pipeline_));
    callback_.reset();
  } else {
    TransparentProxy::tear_down();
  }
}

// ---------------------------------------------------------------------------
// loop_impl
// ---------------------------------------------------------------------------
Status HttpStreamType3Proxy::loop_impl() {
  switch (state_) {
    case State::Init:
      TRY_STATUS(do_init());
      break;
    case State::TlsHandshake:
      TRY_STATUS(wait_tls_handshake());
      break;
    case State::Connected:
      break;
    default:
      UNREACHABLE();
  }
  return Status::OK();
}

}  // namespace td
// === TYPE3-PROXY END ===
