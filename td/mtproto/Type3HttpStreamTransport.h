// === TYPE3-PROXY BEGIN ===
//
// Type3HttpStreamTransport — IStreamTransport implementation over HTTP POST+chunked
// with AES-256-CTR obfuscated-2 encoding per teleproto3 spec/wire-format.md §1.3, §2.2.
//
// Architecture:
//   init()      — sends HTTP POST headers + Session Header + 64-byte obfuscated-2 init
//   write()     — AES-CTR encrypts + wraps in HTTP chunk
//   read_next() — strips HTTP chunk framing, AES-CTR decrypts, extracts intermediate-format packets
//
// Key difference from Type3WebSocketTransport:
//   - No WebSocket framing (no WS upgrade, no masking, no opcodes)
//   - Data framed as HTTP chunks: "<hex-len>\r\n<data>\r\n"
//   - Server responds with "200 OK" + "Transfer-Encoding: chunked"
//   - ТСПУ-safe: looks like a normal HTTPS POST to a REST API
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

#include <atomic>

namespace td {
namespace mtproto {

class Type3HttpStreamTransport final : public IStreamTransport {
 public:
  Type3HttpStreamTransport(int16 dc_id, ProxySecret secret, string host, string path)
      : dc_id_(dc_id), secret_(std::move(secret)), host_(std::move(host)), path_(std::move(path)) {
  }

  // IStreamTransport interface
  Result<size_t> read_next(BufferSlice *message, uint32 *quick_ack) final TD_WARN_UNUSED_RESULT;
  bool support_quick_ack() const final { return false; }
  void write(BufferWriter &&message, bool quick_ack) final;
  bool can_read() const final { return !closed_; }
  bool can_write() const final { return !closed_; }
  void init(ChainBufferReader *input, ChainBufferWriter *output) final;
  size_t max_prepend_size() const final { return 4; }   // 4-byte intermediate-format length prefix
  size_t max_append_size() const final { return 15; }    // up to 15 bytes random padding (padded mode)
  TransportType get_type() const final {
    return TransportType{TransportType::HttpStreamType3, dc_id_, secret_};
  }
  bool use_random_padding() const final { return false; }

 private:
  int16 dc_id_;
  ProxySecret secret_;
  string host_;
  string path_;

  ChainBufferReader *input_{nullptr};
  ChainBufferWriter *output_{nullptr};

  bool closed_{false};

  // HTTP response header parsing state
  bool http_headers_parsed_{false};
  string http_header_buf_;

  // AES-CTR state
  AesCtrState output_aes_;
  AesCtrState input_aes_;

  // Intermediate-format packet reassembly
  string pkt_reassembly_buf_;
  size_t pkt_reassembly_offset_{0};

  // HTTP chunk parser state
  enum class ChunkState { ReadingSize, ReadingData, ReadingTrailer };
  ChunkState chunk_state_{ChunkState::ReadingSize};
  string chunk_size_buf_;
  size_t chunk_remaining_{0};

  // Padding support (Epic 11, Story 11-5)
  bool padding_active_{false};
  bool padding_rejected_{false};

  static std::atomic<bool> g_padding_ever_rejected_;

  static constexpr uint16 T3_FLAG_PADDING = 0x0001;
  static constexpr uint8  T3_PADDING_MARKER = 0xFE;
  static constexpr int    SPLIT_MIN_CHUNKS = 2;
  static constexpr int    SPLIT_MAX_CHUNKS = 5;

  // Send HTTP POST headers + Session Header + 64-byte obfuscated-2 init
  void send_init_sequence();

  // Wrap raw bytes in an HTTP chunk and append to output_
  void append_http_chunk(Slice payload);

  // Try to read and decode one HTTP chunk payload from input_
  // Returns empty BufferSlice if not enough data yet
  Result<BufferSlice> read_http_chunk();

  // Parse HTTP response headers (200 OK)
  bool try_parse_http_response();
};

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
