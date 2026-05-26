// === TYPE3-PROXY BEGIN ===
//
// Type3Transport — unified implementation for WS and HTTP Stream modes.
// Uses libteleproto3 t3_client_crypto for obfs2 KDF + AES-CTR,
// t3_client_ws for WS framing, and t3_http_chunk_* for HTTP chunked framing.
//
#include "td/mtproto/Type3Transport.h"

#include "td/utils/as.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/logging.h"
#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"
#include "td/utils/Status.h"

#include <cstring>

namespace td {
namespace mtproto {

// ---------------------------------------------------------------------------
// init() — generate obfs2 header via libteleproto3, send it framed
// ---------------------------------------------------------------------------
void Type3Transport::init(ChainBufferReader *input, ChainBufferWriter *output) {
  input_ = input;
  output_ = output;
  send_init_sequence();
}

void Type3Transport::send_init_sequence() {
  // Extract 16-byte proxy secret
  Slice proxy_secret = secret_.get_proxy_secret();
  if (proxy_secret.size() < 16) {
    LOG(ERROR) << "Type3Transport: proxy secret too short (" << proxy_secret.size() << " bytes, need >= 16)";
    closed_ = true;
    return;
  }

  // Use libteleproto3 to generate the 64-byte obfs2 init header
  // and initialize AES-CTR encrypt/decrypt contexts
  uint8_t secret_bytes[16];
  std::memcpy(secret_bytes, proxy_secret.data(), 16);

  uint8_t header[64];
  int rc = t3c_obfs2_generate_init(secret_bytes, dc_id_, header, &encrypt_ctx_, &decrypt_ctx_);
  if (rc != 0) {
    LOG(ERROR) << "Type3Transport: obfs2 init generation failed";
    closed_ = true;
    return;
  }
  crypto_initialized_ = true;

  // For HTTP stream mode: send POST headers first
  if (mode_ == Mode::HttpStream) {
    string hdrs = PSTRING() << "POST /" << path_ << " HTTP/1.1\r\n"
                            << "Host: " << host_ << "\r\n"
                            << "Content-Type: application/octet-stream\r\n"
                            << "Transfer-Encoding: chunked\r\n"
                            << "Connection: keep-alive\r\n"
                            << "\r\n";
    output_->append(hdrs);
  }

  // Frame the 64-byte header and send
  append_framed(Slice(reinterpret_cast<const char *>(header), 64));

  LOG(INFO) << "Type3Transport: init complete, mode=" << (mode_ == Mode::WebSocket ? "WS" : "HTTP")
            << " dc_id=" << dc_id_;
}

// ---------------------------------------------------------------------------
// write() — encrypt + frame MTProto payload
// ---------------------------------------------------------------------------
void Type3Transport::write(BufferWriter &&message, bool /*quick_ack*/) {
  if (closed_ || !crypto_initialized_) return;

  auto payload = message.as_buffer_slice();
  auto data = payload.as_slice();

  // AES-CTR encrypt in-place
  string encrypted(data.size(), '\0');
  t3c_aes_crypt(&encrypt_ctx_, reinterpret_cast<const uint8_t *>(data.data()),
                reinterpret_cast<uint8_t *>(&encrypted[0]), data.size());

  // Frame and send
  append_framed(Slice(encrypted));
}

// ---------------------------------------------------------------------------
// append_framed() — wrap payload in WS binary frame or HTTP chunk
// ---------------------------------------------------------------------------
void Type3Transport::append_framed(Slice payload) {
  if (mode_ == Mode::WebSocket) {
    // WS binary frame with masking (client → server)
    size_t frame_cap = payload.size() + 14;  // max WS header overhead
    string frame(frame_cap, '\0');
    size_t frame_len = 0;
    int rc = t3c_ws_frame_write(
        reinterpret_cast<const uint8_t *>(payload.data()), payload.size(),
        reinterpret_cast<uint8_t *>(&frame[0]), frame_cap, &frame_len);
    if (rc != 0) {
      LOG(ERROR) << "Type3Transport: WS frame write failed";
      closed_ = true;
      return;
    }
    output_->append(Slice(frame.data(), frame_len));
  } else {
    // HTTP chunked encoding
    size_t chunk_cap = payload.size() + 32;
    string chunk(chunk_cap, '\0');
    size_t chunk_len = 0;
    t3_result_t rc = t3_http_chunk_write(
        reinterpret_cast<uint8_t *>(&chunk[0]), chunk_cap,
        reinterpret_cast<const uint8_t *>(payload.data()), payload.size(),
        &chunk_len);
    if (rc != T3_OK) {
      LOG(ERROR) << "Type3Transport: HTTP chunk write failed: " << t3_strerror(rc);
      closed_ = true;
      return;
    }
    output_->append(Slice(chunk.data(), chunk_len));
  }
}

// ---------------------------------------------------------------------------
// read_frame() — read one complete frame (WS or HTTP chunk)
// ---------------------------------------------------------------------------
Result<BufferSlice> Type3Transport::read_frame() {
  // Collect available bytes into reassembly buffer
  auto ready = input_->prepare_read();
  if (ready.size() > 0) {
    pkt_reassembly_buf_.append(ready.data(), ready.size());
    input_->confirm_read(ready.size());
  }

  auto available = pkt_reassembly_buf_.size() - pkt_reassembly_offset_;
  if (available == 0) {
    return BufferSlice();  // no data
  }

  const uint8_t *buf = reinterpret_cast<const uint8_t *>(pkt_reassembly_buf_.data()) + pkt_reassembly_offset_;

  if (mode_ == Mode::WebSocket) {
    const uint8_t *payload;
    size_t payload_len, consumed;
    int rc = t3c_ws_frame_read(buf, available, &payload, &payload_len, &consumed);
    if (rc == 1) return BufferSlice();  // need more data
    if (rc < 0) return Status::Error("WS frame parse error");

    BufferSlice result(payload_len);
    std::memcpy(result.as_mutable_slice().data(), payload, payload_len);
    pkt_reassembly_offset_ += consumed;

    // Compact when > 50% consumed
    if (pkt_reassembly_offset_ > pkt_reassembly_buf_.size() / 2) {
      pkt_reassembly_buf_ = pkt_reassembly_buf_.substr(pkt_reassembly_offset_);
      pkt_reassembly_offset_ = 0;
    }

    return std::move(result);
  } else {
    // HTTP chunk
    const uint8_t *data;
    size_t data_len, consumed;
    t3_result_t rc = t3_http_chunk_parse(buf, available, &data, &data_len, &consumed);
    if (rc == T3_ERR_BUF_TOO_SMALL) return BufferSlice();
    if (rc != T3_OK) return Status::Error(PSLICE() << "HTTP chunk parse error: " << t3_strerror(rc));

    if (data_len == 0) {
      // Terminal chunk
      pkt_reassembly_offset_ += consumed;
      return BufferSlice();
    }

    BufferSlice result(data_len);
    std::memcpy(result.as_mutable_slice().data(), data, data_len);
    pkt_reassembly_offset_ += consumed;

    if (pkt_reassembly_offset_ > pkt_reassembly_buf_.size() / 2) {
      pkt_reassembly_buf_ = pkt_reassembly_buf_.substr(pkt_reassembly_offset_);
      pkt_reassembly_offset_ = 0;
    }

    return std::move(result);
  }
}

// ---------------------------------------------------------------------------
// read_next() — deframe + decrypt → extract intermediate-format packets
// ---------------------------------------------------------------------------
Result<size_t> Type3Transport::read_next(BufferSlice *message, uint32 * /*quick_ack*/) {
  if (closed_) return 0;

  while (true) {
    TRY_RESULT(frame, read_frame());
    if (frame.empty()) return 0;  // need more data

    // AES-CTR decrypt
    auto frame_slice = frame.as_mutable_slice();
    t3c_aes_crypt(&decrypt_ctx_,
                  reinterpret_cast<const uint8_t *>(frame_slice.data()),
                  reinterpret_cast<uint8_t *>(frame_slice.data()),
                  frame_slice.size());

    // Skip padding frames (first byte == 0xFE)
    if (frame_slice.size() > 0 && static_cast<uint8_t>(frame_slice[0]) == 0xFE) {
      continue;
    }

    // Extract intermediate-format packets
    // The decrypted data contains: 4-byte LE length + payload
    // Multiple packets may be in one frame
    size_t offset = 0;
    while (offset + 4 <= frame_slice.size()) {
      uint32 pkt_len = as<uint32>(frame_slice.data() + offset);
      pkt_len &= 0x00FFFFFF;  // clear quickack bit
      if (pkt_len == 0 || offset + 4 + pkt_len > frame_slice.size()) {
        break;
      }
      *message = BufferSlice(frame_slice.substr(offset + 4, pkt_len));
      return pkt_len;
    }
  }
}

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
