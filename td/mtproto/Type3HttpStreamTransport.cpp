// === TYPE3-PROXY BEGIN ===
//
// Type3HttpStreamTransport — implementation
// See header for architecture notes.
//
#include "td/mtproto/Type3HttpStreamTransport.h"

#include "td/utils/as.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/crypto.h"
#include "td/utils/logging.h"
#include "td/utils/Random.h"
#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"
#include "td/utils/Status.h"

#include <cstring>

namespace td {
namespace mtproto {

std::atomic<bool> Type3HttpStreamTransport::g_padding_ever_rejected_{false};

// ---------------------------------------------------------------------------
// init() — sends HTTP POST + Session Header + 64-byte obfuscated-2 init
// ---------------------------------------------------------------------------
void Type3HttpStreamTransport::init(ChainBufferReader *input, ChainBufferWriter *output) {
  input_ = input;
  output_ = output;
  send_init_sequence();
}

void Type3HttpStreamTransport::send_init_sequence() {
  // ---- Build Session Header + 64-byte obfuscated-2 init ----
  // Identical to Type3WebSocketTransport::send_init_sequence() for the crypto
  // part. Only the framing layer differs (HTTP chunks vs WS frames).

  const size_t HEADER_SIZE = 64;
  char header[HEADER_SIZE];

  for (int attempt = 0; attempt < 10; attempt++) {
    Random::secure_bytes(MutableSlice(header, HEADER_SIZE));
    uint32 first_int = as<uint32>(header);
    if (first_int == 0x44414548 || first_int == 0x54534f50 || first_int == 0x20544547 ||
        first_int == 0x4954504f || first_int == 0x02010316 ||
        static_cast<uint8>(header[0]) == 0xef) {
      continue;
    }
    if (first_int == 0xeeeeeeee || first_int == 0xdddddddd) {
      continue;
    }
    break;
  }

  // Type3 Session Header at bytes [0:3]
  padding_rejected_ = g_padding_ever_rejected_.load(std::memory_order_relaxed);
  header[0] = 0x01;  // command_type = MTPROTO_PASSTHROUGH
  header[1] = 0x01;  // version = 1
  uint16 flags = padding_rejected_ ? 0x0000 : T3_FLAG_PADDING;
  header[2] = static_cast<char>(flags & 0xFF);
  header[3] = static_cast<char>((flags >> 8) & 0xFF);
  padding_active_ = !padding_rejected_;

  // Magic tag 0xDDDDDDDD (intermediate padding mode)
  as<uint32>(header + 56) = 0xdddddddd;

  // DC ID
  as<int16>(header + 60) = dc_id_;

  // ---- Derive keys (identical to WS transport) ----
  Slice proxy_secret = secret_.get_proxy_secret();
  if (proxy_secret.size() < 16) {
    LOG(ERROR) << "Type3HttpStream: proxy secret too short (" << proxy_secret.size() << " bytes, need >= 16)";
    closed_ = true;
    return;
  }

  // send_key = SHA256(header[8..40] || proxy_secret[0..16])
  UInt256 send_key;
  {
    Sha256State state;
    state.init();
    state.feed(Slice(header + 8, 32));
    state.feed(proxy_secret);
    state.extract(as_mutable_slice(send_key));
  }
  UInt128 send_iv = as<UInt128>(header + 40);

  // recv_key = SHA256(reverse(header[24..56]) || proxy_secret[0..16])
  char rev_buf[32];
  std::memcpy(rev_buf, header + 24, 32);
  std::reverse(rev_buf, rev_buf + 32);
  UInt256 recv_key;
  {
    Sha256State state;
    state.init();
    state.feed(Slice(rev_buf, 32));
    state.feed(proxy_secret);
    state.extract(as_mutable_slice(recv_key));
  }
  char rev_iv_buf[16];
  std::memcpy(rev_iv_buf, header + 8, 16);
  std::reverse(rev_iv_buf, rev_iv_buf + 16);
  UInt128 recv_iv = as<UInt128>(rev_iv_buf);

  // Initialise AES-CTR states
  output_aes_.init(as_slice(send_key), as_slice(send_iv));
  input_aes_.init(as_slice(recv_key), as_slice(recv_iv));

  // ---- Encrypt-then-restore ----
  char header_copy[HEADER_SIZE];
  std::memcpy(header_copy, header, HEADER_SIZE);
  output_aes_.encrypt(Slice(header_copy, HEADER_SIZE), MutableSlice(header, HEADER_SIZE));
  std::memcpy(header, header_copy, 56);  // restore bytes 0..55 to plaintext

  // ---- Build HTTP POST request + first chunk (Session Header + obfs2 init) ----
  // The first 4 bytes of the chunked payload stream are the Session Header,
  // but those are already embedded in header[0..3]. So we send the full 64 bytes
  // as the first HTTP chunk.

  string path = path_.empty() ? "/" : "/" + path_;

  // HTTP request headers
  string http_req = "POST " + path + " HTTP/1.1\r\n"
                    "Host: " + host_ + "\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n";

  output_->append(http_req);

  // Send the 64-byte init as the first HTTP chunk
  append_http_chunk(Slice(header, HEADER_SIZE));
}

// ---------------------------------------------------------------------------
// HTTP chunk helper — wraps payload in "<hex-len>\r\n<data>\r\n"
// ---------------------------------------------------------------------------
void Type3HttpStreamTransport::append_http_chunk(Slice payload) {
  if (payload.empty()) {
    return;
  }

  // Format: "<hex-len>\r\n"
  char size_buf[32];
  int size_len = snprintf(size_buf, sizeof(size_buf), "%x\r\n", static_cast<unsigned>(payload.size()));
  output_->append(Slice(size_buf, size_len));

  // Payload
  output_->append(payload);

  // Trailing "\r\n"
  output_->append(Slice("\r\n", 2));
}

// ---------------------------------------------------------------------------
// write() — encrypt + send one MTProto packet as HTTP chunk(s)
// ---------------------------------------------------------------------------
void Type3HttpStreamTransport::write(BufferWriter &&message, bool quick_ack) {
  // Step 1: Append random padding (0-15 bytes) for padded intermediate mode
  size_t original_size = message.size();
  size_t append_size = Random::secure_uint32() % 16;
  if (append_size > 0) {
    MutableSlice append_area = message.prepare_append().substr(0, append_size);
    CHECK(append_area.size() == append_size);
    Random::secure_bytes(append_area);
    message.confirm_append(append_size);
  }

  // Step 2: Prepend 4-byte intermediate-format length
  MutableSlice prepend_area = message.prepare_prepend();
  CHECK(prepend_area.size() >= 4);
  message.confirm_prepend(4);

  uint32 wire_length = static_cast<uint32>(original_size + append_size);
  if (quick_ack) {
    wire_length |= (1u << 31);
  }
  as<uint32>(message.as_mutable_slice().begin()) = wire_length;

  // Step 3: AES-CTR encrypt in-place
  auto slice = message.as_mutable_slice();
  output_aes_.encrypt(slice, slice);

  // Step 4: Send as HTTP chunk(s)
  auto encrypted_slice = message.as_slice();
  if (padding_active_ && encrypted_slice.size() > 0) {
    // Split into 2-5 random HTTP chunks for traffic analysis resistance
    int n_chunks = SPLIT_MIN_CHUNKS + (Random::secure_uint32() % (SPLIT_MAX_CHUNKS - SPLIT_MIN_CHUNKS + 1));
    size_t remaining = encrypted_slice.size();
    size_t offset = 0;
    for (int i = 0; i < n_chunks && remaining > 0; i++) {
      size_t chunk_size;
      if (i == n_chunks - 1 || remaining <= static_cast<size_t>(n_chunks - i)) {
        chunk_size = remaining;
      } else {
        size_t max_chunk = remaining - static_cast<size_t>(n_chunks - i - 1);
        chunk_size = 1 + (Random::secure_uint32() % static_cast<uint32>(max_chunk));
      }
      append_http_chunk(encrypted_slice.substr(offset, chunk_size));
      offset += chunk_size;
      remaining -= chunk_size;
    }
  } else {
    append_http_chunk(encrypted_slice);
  }
}

// ---------------------------------------------------------------------------
// try_parse_http_response() — parse "HTTP/1.1 200 OK\r\n...\r\n\r\n"
// Returns true when headers are fully consumed, false if more data needed.
// ---------------------------------------------------------------------------
bool Type3HttpStreamTransport::try_parse_http_response() {
  input_->sync_with_writer();
  LOG(WARNING) << "T3_HTTP_PARSE: input size=" << input_->size() << " headers_parsed=" << http_headers_parsed_
               << " header_buf_size=" << http_header_buf_.size();
  if (input_->size() > 0 && http_header_buf_.empty()) {
    // Dump first 64 bytes as hex for diagnosis
    size_t dump_len = std::min(input_->size(), static_cast<size_t>(256));
    auto slice = input_->prepare_read();
    size_t actual = std::min(dump_len, slice.size());
    string hex;
    string ascii;
    for (size_t i = 0; i < actual; i++) {
      char buf[4];
      snprintf(buf, sizeof(buf), "%02x ", static_cast<unsigned char>(slice[i]));
      hex += buf;
      ascii += (slice[i] >= 32 && slice[i] < 127) ? slice[i] : '.';
    }
    LOG(WARNING) << "T3_HTTP_DUMP: actual=" << actual << "/" << dump_len << " ascii=[" << ascii << "]";
  }

  while (input_->size() > 0) {
    char c;
    input_->advance(1, MutableSlice(&c, 1));
    http_header_buf_ += c;

    // Check for end of headers: "\r\n\r\n"
    if (http_header_buf_.size() >= 4 &&
        http_header_buf_.substr(http_header_buf_.size() - 4) == "\r\n\r\n") {
      // Validate it starts with "HTTP/1.1 200"
      if (http_header_buf_.substr(0, 12) != "HTTP/1.1 200") {
        LOG(ERROR) << "Type3HttpStream: unexpected response: " << http_header_buf_.substr(0, 40);
        closed_ = true;
        return true;  // parsed (but failed)
      }
      http_headers_parsed_ = true;
      return true;
    }

    // Safety: cap header size
    if (http_header_buf_.size() > 4096) {
      LOG(ERROR) << "Type3HttpStream: HTTP response headers exceed 4KB";
      closed_ = true;
      return true;
    }
  }
  // Post-loop diagnostic
  if (!http_headers_parsed_ && !http_header_buf_.empty()) {
    auto pos = http_header_buf_.find("\r\n\r\n");
    LOG(WARNING) << "T3_HTTP_POST: consumed " << http_header_buf_.size() << " bytes, \\r\\n\\r\\n at pos=" 
                 << (pos == string::npos ? -1 : static_cast<int>(pos))
                 << " last4=[" << (http_header_buf_.size() >= 4 ? http_header_buf_.substr(http_header_buf_.size() - 4) : "<short>") << "]";
  }
  return false;  // need more data
}

// ---------------------------------------------------------------------------
// read_http_chunk() — consume one HTTP chunk payload from input_
// Returns empty BufferSlice if more data needed.
// ---------------------------------------------------------------------------
Result<BufferSlice> Type3HttpStreamTransport::read_http_chunk() {
  size_t available = input_->size();
  if (available == 0) {
    return BufferSlice();
  }

  while (true) {
    available = input_->size();
    if (available == 0) {
      return BufferSlice();
    }

    switch (chunk_state_) {
      case ChunkState::ReadingSize: {
        // Read bytes until we see "\r\n"
        while (input_->size() > 0) {
          char c;
          input_->advance(1, MutableSlice(&c, 1));
          chunk_size_buf_ += c;

          if (chunk_size_buf_.size() >= 2 &&
              chunk_size_buf_.substr(chunk_size_buf_.size() - 2) == "\r\n") {
            // Parse hex size (strip trailing \r\n)
            string hex_str = chunk_size_buf_.substr(0, chunk_size_buf_.size() - 2);
            // Strip chunk extensions (after semicolon)
            auto semi = hex_str.find(';');
            if (semi != string::npos) {
              hex_str = hex_str.substr(0, semi);
            }
            chunk_size_buf_.clear();

            unsigned long parsed_size = 0;
            for (auto c : hex_str) {
              if (c >= '0' && c <= '9') {
                parsed_size = parsed_size * 16 + static_cast<unsigned long>(c - '0');
              } else if (c >= 'a' && c <= 'f') {
                parsed_size = parsed_size * 16 + static_cast<unsigned long>(c - 'a' + 10);
              } else if (c >= 'A' && c <= 'F') {
                parsed_size = parsed_size * 16 + static_cast<unsigned long>(c - 'A' + 10);
              } else {
                return Status::Error("Type3HttpStream: invalid hex char in chunk size");
              }
            }
            if (hex_str.empty()) {
              return Status::Error("Type3HttpStream: empty chunk size");
            }

            if (parsed_size == 0) {
              // Terminal chunk — connection ends
              closed_ = true;
              return BufferSlice();
            }

            if (parsed_size > 65535) {
              return Status::Error("Type3HttpStream: chunk size exceeds 64KB limit");
            }

            chunk_remaining_ = static_cast<size_t>(parsed_size);
            chunk_state_ = ChunkState::ReadingData;
            break;
          }

          // Safety: chunk size line shouldn't exceed 32 bytes
          if (chunk_size_buf_.size() > 300) {
            return Status::Error("Type3HttpStream: chunk size line too long");
          }
        }
        if (chunk_state_ != ChunkState::ReadingData) {
          return BufferSlice();  // need more data for size line
        }
        break;
      }

      case ChunkState::ReadingData: {
        if (input_->size() < chunk_remaining_) {
          return BufferSlice();  // need more data
        }

        // Consume chunk_remaining_ bytes
        BufferSlice payload = input_->cut_head(chunk_remaining_).move_as_buffer_slice();
        chunk_remaining_ = 0;
        chunk_state_ = ChunkState::ReadingTrailer;

        // If we have the trailing \r\n already, consume it now
        if (input_->size() >= 2) {
          char trailer[2];
          input_->advance(2, MutableSlice(trailer, 2));
          // Should be "\r\n" — ignore if not
          chunk_state_ = ChunkState::ReadingSize;
        }

        return payload;
      }

      case ChunkState::ReadingTrailer: {
        if (input_->size() < 2) {
          return BufferSlice();
        }
        char trailer[2];
        input_->advance(2, MutableSlice(trailer, 2));
        chunk_state_ = ChunkState::ReadingSize;
        break;  // continue to next chunk
      }
    }
  }
}

// ---------------------------------------------------------------------------
// read_next() — read one decoded MTProto packet from the input stream
// ---------------------------------------------------------------------------
Result<size_t> Type3HttpStreamTransport::read_next(BufferSlice *message, uint32 *quick_ack) {
  if (closed_) {
    return Status::Error("HTTP stream connection closed");
  }

  input_->sync_with_writer();

  // Phase 1: Parse HTTP response headers if not yet done
  if (!http_headers_parsed_) {
    if (!try_parse_http_response()) {
      return 1;  // need more data
    }
    if (closed_) {
      return Status::Error("HTTP stream: bad response");
    }
  }

  // Phase 2: Read HTTP chunks and decrypt
  while (true) {
    TRY_RESULT(chunk_payload, read_http_chunk());
    if (chunk_payload.size() == 0) {
      if (closed_) {
        return Status::Error("HTTP stream terminated");
      }
      return 1;  // need more data
    }

    // AES-CTR decrypt in-place
    auto mslice = chunk_payload.as_mutable_slice();
    input_aes_.encrypt(mslice, mslice);  // CTR mode: encrypt == decrypt

    // Padding frame detection: first decrypted byte == 0xFE → discard
    if (padding_active_ && chunk_payload.size() > 0 &&
        static_cast<uint8>(chunk_payload.as_slice()[0]) == T3_PADDING_MARKER) {
      continue;  // CTR counter already advanced, skip padding
    }

    // Accumulate in packet reassembly buffer
    pkt_reassembly_buf_.append(chunk_payload.as_slice().data(), chunk_payload.size());

    // Try to extract one intermediate-format packet (4-byte LE length + payload)
    size_t avail = pkt_reassembly_buf_.size() - pkt_reassembly_offset_;
    if (avail < 4) {
      continue;
    }

    uint32 pkt_len = as<uint32>(pkt_reassembly_buf_.data() + pkt_reassembly_offset_);
    if (pkt_len > (1u << 22) + 1024) {
      return Status::Error("Type3HttpStream: oversized MTProto packet length");
    }
    if (pkt_len < 8) {
      return Status::Error("Type3HttpStream: undersized MTProto packet length");
    }

    if (avail < 4 + pkt_len) {
      continue;  // need more chunks
    }

    // Emit the packet (without the 4-byte length prefix)
    *message = BufferSlice(Slice(pkt_reassembly_buf_.data() + pkt_reassembly_offset_ + 4, pkt_len));
    pkt_reassembly_offset_ += 4 + pkt_len;

    // Compact buffer
    if (pkt_reassembly_offset_ > pkt_reassembly_buf_.size() / 2) {
      pkt_reassembly_buf_.erase(0, pkt_reassembly_offset_);
      pkt_reassembly_offset_ = 0;
    }
    return 0;  // packet is ready
  }
}

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
