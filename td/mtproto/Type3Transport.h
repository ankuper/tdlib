// === TYPE3-PROXY BEGIN ===
//
// Type3Transport — unified IStreamTransport implementation for all Type3 modes
// (WebSocket and HTTP Stream) using libteleproto3 client crypto + framing.
//
// This replaces both Type3WebSocketTransport and Type3HttpStreamTransport.
// Crypto (obfs2 KDF + AES-256-CTR) and framing (WS/HTTP chunked) are
// provided by libteleproto3 via t3_client_crypto.h and t3_client_ws.h.
//
// TLS is handled by tdlib's existing SslStream/TlsPipeline (via proxy actors).
//
#pragma once

#include "td/mtproto/IStreamTransport.h"
#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/TransportType.h"

#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/Status.h"

// libteleproto3 client-side crypto and framing
#include "t3_client_crypto.h"
#include "t3_client_ws.h"
#include "t3.h"

#include <atomic>

namespace td {
namespace mtproto {

class Type3Transport final : public IStreamTransport {
 public:
  enum class Mode { WebSocket, HttpStream };

  Type3Transport(int16 dc_id, ProxySecret secret, Mode mode, string host = {}, string path = {})
      : dc_id_(dc_id), secret_(std::move(secret)), mode_(mode),
        host_(std::move(host)), path_(std::move(path)) {
  }

  // IStreamTransport interface
  Result<size_t> read_next(BufferSlice *message, uint32 *quick_ack) final TD_WARN_UNUSED_RESULT;
  bool support_quick_ack() const final { return false; }
  void write(BufferWriter &&message, bool quick_ack) final;
  bool can_read() const final { return !closed_; }
  bool can_write() const final { return !closed_; }
  void init(ChainBufferReader *input, ChainBufferWriter *output) final;
  size_t max_prepend_size() const final { return 4; }
  size_t max_append_size() const final { return 15; }
  TransportType get_type() const final {
    if (mode_ == Mode::WebSocket) {
      return TransportType{TransportType::WebSocketType3, dc_id_, secret_};
    }
    return TransportType{TransportType::HttpStreamType3, dc_id_, secret_, host_, path_};
  }
  bool use_random_padding() const final { return false; }

 private:
  int16 dc_id_;
  ProxySecret secret_;
  Mode mode_;
  string host_;
  string path_;

  ChainBufferReader *input_{nullptr};
  ChainBufferWriter *output_{nullptr};

  bool closed_{false};

  // libteleproto3 AES-CTR contexts
  t3c_aes_ctx encrypt_ctx_{};
  t3c_aes_ctx decrypt_ctx_{};
  bool crypto_initialized_{false};

  // Packet reassembly buffer
  string pkt_reassembly_buf_;
  size_t pkt_reassembly_offset_{0};

  void send_init_sequence();
  void append_framed(Slice payload);
  Result<BufferSlice> read_frame();
};

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
