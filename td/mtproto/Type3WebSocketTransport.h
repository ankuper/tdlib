// === TYPE3-PROXY BEGIN ===
//
// Type3WebSocketTransport — IStreamTransport implementation over WebSocket frames
// with AES-256-CTR obfuscated-2 encoding per teleproto3 spec/wire-format.md §4.
//
// Architecture:
//   init()   — sends 64-byte obfuscated-2 init (matching tdesktop), derives AES-CTR keys
//   write()  — AES-CTR encrypts + wraps in WS binary frame
//   read_next() — strips WS framing, AES-CTR decrypts, extracts intermediate-format packets
//
#pragma once

#include "td/mtproto/IStreamTransport.h"
#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/TransportType.h"

#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/crypto.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"

namespace td {
namespace mtproto {

class Type3WebSocketTransport final : public IStreamTransport {
 public:
  Type3WebSocketTransport(int16 dc_id, ProxySecret secret)
      : dc_id_(dc_id), secret_(std::move(secret)) {
  }

  // IStreamTransport interface
  Result<size_t> read_next(BufferSlice *message, uint32 *quick_ack) final TD_WARN_UNUSED_RESULT;
  bool support_quick_ack() const final { return false; }
  void write(BufferWriter &&message, bool quick_ack) final;
  bool can_read() const final { return !ws_closed_; }
  bool can_write() const final { return !ws_closed_; }
  void init(ChainBufferReader *input, ChainBufferWriter *output) final;
  size_t max_prepend_size() const final { return 14; }  // 2 + 8 (ext len) + 4 (mask key) worst case
  size_t max_append_size() const final { return 0; }
  TransportType get_type() const final {
    return TransportType{TransportType::WebSocketType3, dc_id_, secret_};
  }
  bool use_random_padding() const final { return false; }

 private:
  int16 dc_id_;
  ProxySecret secret_;

  ChainBufferReader *input_{nullptr};
  ChainBufferWriter *output_{nullptr};

  bool ws_closed_{false};

  // AES-CTR state for the outgoing (write) direction
  AesCtrState output_aes_;
  // AES-CTR state for the incoming (read) direction
  AesCtrState input_aes_;


  // Intermediate-format packet reassembly (with read offset to avoid O(n²) erase)
  string pkt_reassembly_buf_;
  size_t pkt_reassembly_offset_{0};

  // Send 64-byte obfuscated-2 init with encrypt-then-restore; derive AES-CTR keys.
  void send_init_sequence();

  // Wrap raw (already AES-CTR encrypted) bytes in a WS binary frame and append to output_.
  void append_ws_frame(Slice payload);

  // Read one complete WS frame from input_. Returns OK with empty slice if not enough data yet.
  // On WS close frame sets ws_closed_ = true. On ping, queues a pong.
  // Returns error on protocol violation.
  Result<BufferSlice> read_ws_frame();


};

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
