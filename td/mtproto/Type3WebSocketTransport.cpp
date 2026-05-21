// === TYPE3-PROXY BEGIN ===
//
// Type3WebSocketTransport — implementation
// See header for architecture notes.
//
#include "td/mtproto/Type3WebSocketTransport.h"

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

// ---------------------------------------------------------------------------
// init() — sends 64-byte obfuscated-2 init, derives AES-CTR keys
// Matches tdesktop's ConnectionTeleproto3::onWsConnected() flow.
// ---------------------------------------------------------------------------
void Type3WebSocketTransport::init(ChainBufferReader *input, ChainBufferWriter *output) {
  input_ = input;
  output_ = output;
  send_init_sequence();
}

void Type3WebSocketTransport::send_init_sequence() {
  // ---- 64-byte obfuscated-2 init (matches tdesktop's ConnectionTeleproto3) ----
  //
  // Layout per obfuscated-2 protocol (server-side obfs2_parse_header):
  //   bytes  0-7   : random (not used for KDF)
  //   bytes  8-39  : 32 bytes used in send_key derivation (server: read_key)
  //   bytes 24-55  : 32 bytes used (reversed) in recv_key derivation (server: write_key)
  //   bytes  8-23  : 16 bytes used (reversed) in recv_iv (server: write_iv)
  //   bytes 40-55  : 16 bytes used in send_iv (server: read_iv)
  //   bytes 56-59  : plaintext magic tag (0xDDDDDDDD = intermediate padding mode)
  //   bytes 60-61  : DC ID (signed int16, little-endian)
  //   bytes 62-63  : random
  //
  // KDF (client perspective — matches tdesktop exactly):
  //   send_key = SHA256(header[8..40]  || proxy_secret[0..16])
  //   send_iv  = header[40..56]
  //   recv_key = SHA256(reverse(header[24..56]) || proxy_secret[0..16])
  //   recv_iv  = reverse(header[8..24])
  //
  // After key derivation, encrypt all 64 bytes with send AES-CTR (advances the
  // CTR state by 4 blocks = 64 bytes). Then restore plaintext for bytes 0..55
  // (server derives keys from those plaintext bytes). Bytes 56..63 stay encrypted
  // on the wire — the server decrypts them with its read_key to verify the magic.

  const size_t HEADER_SIZE = 64;
  char header[HEADER_SIZE];

  for (int attempt = 0; attempt < 10; attempt++) {
    Random::secure_bytes(MutableSlice(header, HEADER_SIZE));
    // Avoid HTTP-look-alike magic at bytes 0-3 (anti-probe)
    uint32 first_int = as<uint32>(header);
    if (first_int == 0x44414548 || first_int == 0x54534f50 || first_int == 0x20544547 ||
        first_int == 0x4954504f || first_int == 0x02010316 ||
        static_cast<uint8>(header[0]) == 0xef) {
      continue;
    }
    // Also avoid magic tags in plaintext bytes 56-59 matching reserved patterns
    if (first_int == 0xeeeeeeee || first_int == 0xdddddddd) {
      continue;
    }
    break;
  }

  // Write plaintext magic at bytes [56..60): 0xDDDDDDDD (intermediate padding mode)
  as<uint32>(header + 56) = 0xdddddddd;

  // Write DC ID at bytes [60..62) (signed int16, little-endian)
  as<int16>(header + 60) = dc_id_;

  // ---- Derive keys ----
  Slice proxy_secret = secret_.get_proxy_secret();  // 16-byte AES secret
  if (proxy_secret.size() < 16) {
    LOG(ERROR) << "Type3WebSocket: proxy secret too short (" << proxy_secret.size() << " bytes, need >= 16)";
    ws_closed_ = true;
    return;
  }

  // DEBUG: dump proxy_secret
  {
    string hex;
    for (size_t i = 0; i < proxy_secret.size(); i++) {
      char buf[3]; snprintf(buf, sizeof(buf), "%02x", (unsigned char)proxy_secret[i]);
      hex += buf;
    }
    LOG(WARNING) << "T3_DEBUG: proxy_secret(" << proxy_secret.size() << ")=" << hex;
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
  // send_iv = header[40..56]
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
  // recv_iv = reverse(header[8..24])
  char rev_iv_buf[16];
  std::memcpy(rev_iv_buf, header + 8, 16);
  std::reverse(rev_iv_buf, rev_iv_buf + 16);
  UInt128 recv_iv = as<UInt128>(rev_iv_buf);

  // DEBUG: dump keys and header before encryption
  {
    string hdr_hex, key_hex, iv_hex;
    for (size_t i = 0; i < HEADER_SIZE; i++) {
      char buf[3]; snprintf(buf, sizeof(buf), "%02x", (unsigned char)header[i]);
      hdr_hex += buf;
    }
    auto key_slice = as_slice(send_key);
    for (size_t i = 0; i < key_slice.size(); i++) {
      char buf[3]; snprintf(buf, sizeof(buf), "%02x", (unsigned char)key_slice[i]);
      key_hex += buf;
    }
    auto iv_slice = as_slice(send_iv);
    for (size_t i = 0; i < iv_slice.size(); i++) {
      char buf[3]; snprintf(buf, sizeof(buf), "%02x", (unsigned char)iv_slice[i]);
      iv_hex += buf;
    }
    LOG(WARNING) << "T3_DEBUG: plaintext_header=" << hdr_hex;
    LOG(WARNING) << "T3_DEBUG: send_key=" << key_hex;
    LOG(WARNING) << "T3_DEBUG: send_iv=" << iv_hex;
  }

  // Initialise AES-CTR states (continuous across all WS frames — no per-frame reset)
  output_aes_.init(as_slice(send_key), as_slice(send_iv));
  input_aes_.init(as_slice(recv_key), as_slice(recv_iv));

  // ---- Encrypt-then-restore (critical for CTR state synchronisation) ----
  // Encrypt the FULL 64-byte nonce with the output (send) AES-CTR.
  // This advances the CTR counter by 4 blocks. The server does the same
  // (evp_crypt(read_aeskey, header, header, 64)) to advance its read CTR.
  // Then restore bytes 0..55 to plaintext — server derives keys from those.
  // Bytes 56..63 stay encrypted — server decrypts to verify magic + DC ID.
  char header_copy[HEADER_SIZE];
  std::memcpy(header_copy, header, HEADER_SIZE);  // save plaintext

  output_aes_.encrypt(Slice(header_copy, HEADER_SIZE), MutableSlice(header, HEADER_SIZE));

  // Restore bytes 0..55 to plaintext (server needs these unencrypted for KDF)
  std::memcpy(header, header_copy, 56);

  // DEBUG: dump wire header
  {
    string wire_hex;
    for (size_t i = 0; i < HEADER_SIZE; i++) {
      char buf[3]; snprintf(buf, sizeof(buf), "%02x", (unsigned char)header[i]);
      wire_hex += buf;
    }
    LOG(WARNING) << "T3_DEBUG: wire_header=" << wire_hex;
    // Dump encrypted bytes 56-63 separately
    string enc_hex;
    for (size_t i = 56; i < 64; i++) {
      char buf[3]; snprintf(buf, sizeof(buf), "%02x", (unsigned char)header[i]);
      enc_hex += buf;
    }
    LOG(WARNING) << "T3_DEBUG: encrypted_tag_bytes=" << enc_hex;
  }

  // Send the 64-byte init as a single WS binary frame
  append_ws_frame(Slice(header, HEADER_SIZE));
}

// ---------------------------------------------------------------------------
// WS binary frame helper
// Client→Server frames MUST be masked (RFC 6455 §5.3).
// ---------------------------------------------------------------------------
void Type3WebSocketTransport::append_ws_frame(Slice payload) {
  // WS frame format (client→server, binary, FIN=1):
  //   byte 0: 0x82  (FIN=1, opcode=0x2 binary)
  //   byte 1: 0x80 | length_indicator  (MASK=1)
  //   [extended length: 2 or 8 bytes if needed]
  //   [4-byte masking key]
  //   [masked payload]
  const size_t len = payload.size();

  // Build header
  string frame_header;
  frame_header += '\x82';  // FIN + binary opcode

  if (len <= 125) {
    frame_header += static_cast<char>(0x80 | len);
  } else if (len <= 65535) {
    frame_header += static_cast<char>(0xFE);  // 0x80 | 126
    frame_header += static_cast<char>((len >> 8) & 0xFF);
    frame_header += static_cast<char>(len & 0xFF);
  } else {
    frame_header += static_cast<char>(0xFF);  // 0x80 | 127
    for (int i = 7; i >= 0; i--) {
      frame_header += static_cast<char>((len >> (8 * i)) & 0xFF);
    }
  }

  // 4-byte masking key
  uint8 mask[4];
  Random::secure_bytes(MutableSlice(reinterpret_cast<char *>(mask), 4));
  frame_header += static_cast<char>(mask[0]);
  frame_header += static_cast<char>(mask[1]);
  frame_header += static_cast<char>(mask[2]);
  frame_header += static_cast<char>(mask[3]);

  output_->append(frame_header);

  // Masked payload
  string masked(len, '\0');
  const auto *src = reinterpret_cast<const uint8 *>(payload.data());
  for (size_t i = 0; i < len; i++) {
    masked[i] = static_cast<char>(src[i] ^ mask[i % 4]);
  }
  output_->append(masked);
}

// ---------------------------------------------------------------------------
// write() — encrypt + send one MTProto packet as a WS binary frame
// Prepends the 4-byte intermediate-format length prefix and optional random
// padding (for tag=0xdddddddd padded mode), then AES-CTR encrypts the lot.
// ---------------------------------------------------------------------------
void Type3WebSocketTransport::write(BufferWriter &&message, bool quick_ack) {
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
  // Length = payload + padding (does NOT include the 4-byte prefix itself)
  MutableSlice prepend_area = message.prepare_prepend();
  CHECK(prepend_area.size() >= 4);
  message.confirm_prepend(4);

  // Write the length at the start of the expanded buffer
  uint32 wire_length = static_cast<uint32>(original_size + append_size);
  if (quick_ack) {
    wire_length |= (1u << 31);
  }
  as<uint32>(message.as_mutable_slice().begin()) = wire_length;

  // Step 3: AES-CTR encrypt in-place (length + payload + padding)
  auto slice = message.as_mutable_slice();
  output_aes_.encrypt(slice, slice);

  // Step 4: Wrap in WS binary frame and append to output buffer
  append_ws_frame(message.as_slice());
}

// ---------------------------------------------------------------------------
// read_next() — read one decoded MTProto packet from the input stream
// ---------------------------------------------------------------------------
Result<size_t> Type3WebSocketTransport::read_next(BufferSlice *message, uint32 *quick_ack) {
  if (ws_closed_) {
    return Status::Error("WebSocket connection closed");
  }

  // Ensure the reader sees all data that the network writer has appended
  input_->sync_with_writer();

  while (true) {
    // Try to extract a complete WS frame
    TRY_RESULT(frame_payload, read_ws_frame());
    if (frame_payload.size() == 0) {
      // Not enough data yet — need at least 2 bytes for a WS frame header
      return input_->size() < 2 ? 2 : 1;
    }

    // AES-CTR decrypt the payload in-place
    auto mslice = frame_payload.as_mutable_slice();
    input_aes_.encrypt(mslice, mslice);  // AesCtrState::encrypt is CTR (same for enc/dec)

    // Accumulate in packet reassembly buffer
    pkt_reassembly_buf_.append(frame_payload.as_slice().data(), frame_payload.size());

    // Try to extract one intermediate-format packet (4-byte LE length + payload)
    size_t avail = pkt_reassembly_buf_.size() - pkt_reassembly_offset_;
    if (avail < 4) {
      continue;
    }

    uint32 pkt_len = as<uint32>(pkt_reassembly_buf_.data() + pkt_reassembly_offset_);
    // Sanity: intermediate-format packets are ≤4MB and ≥8 bytes
    if (pkt_len > (1u << 22) + 1024) {
      return Status::Error("Type3WebSocket: oversized MTProto packet length");
    }
    if (pkt_len < 8) {
      return Status::Error("Type3WebSocket: undersized MTProto packet length");
    }

    if (avail < 4 + pkt_len) {
      continue;  // need more WS frames
    }

    // Emit the packet (without the 4-byte length prefix)
    *message = BufferSlice(Slice(pkt_reassembly_buf_.data() + pkt_reassembly_offset_ + 4, pkt_len));
    pkt_reassembly_offset_ += 4 + pkt_len;

    // Compact buffer when offset exceeds half the total size to bound memory
    if (pkt_reassembly_offset_ > pkt_reassembly_buf_.size() / 2) {
      pkt_reassembly_buf_.erase(0, pkt_reassembly_offset_);
      pkt_reassembly_offset_ = 0;
    }
    return 0;  // packet is ready
  }
}

// ---------------------------------------------------------------------------
// read_ws_frame() — consume one complete WS frame from input_
// Returns: empty BufferSlice if more data needed, or payload on success.
// Sets ws_closed_ on opcode 0x8. Sends pong on opcode 0x9.
// ---------------------------------------------------------------------------
Result<BufferSlice> Type3WebSocketTransport::read_ws_frame() {
  size_t available = input_->size();
  if (available < 2) {
    return BufferSlice();
  }

  // Peek at first 2 bytes without consuming
  auto it = input_->clone();
  uint8 b0, b1;
  char tmp[2];
  it.advance(2, MutableSlice(tmp, 2));
  b0 = static_cast<uint8>(tmp[0]);
  b1 = static_cast<uint8>(tmp[1]);

  uint8 opcode = b0 & 0x0F;
  bool masked = (b1 & 0x80) != 0;
  uint64 payload_len = b1 & 0x7F;

  size_t header_len = 2;
  if (payload_len == 126) {
    header_len += 2;
  } else if (payload_len == 127) {
    header_len += 8;
  }
  if (masked) {
    header_len += 4;
  }

  if (available < header_len) {
    return BufferSlice();
  }

  // Now peek the full header
  it = input_->clone();
  string hdr(header_len, '\0');
  it.advance(header_len, MutableSlice(&hdr[0], header_len));

  if (payload_len == 126) {
    payload_len = (static_cast<uint64>(static_cast<uint8>(hdr[2])) << 8) |
                  static_cast<uint64>(static_cast<uint8>(hdr[3]));
  } else if (payload_len == 127) {
    payload_len = 0;
    for (int i = 0; i < 8; i++) {
      payload_len = (payload_len << 8) | static_cast<uint64>(static_cast<uint8>(hdr[2 + i]));
    }
  }

  // P6: cap incoming WS frame size to prevent OOM from malicious/buggy server
  constexpr uint64 MAX_WS_FRAME_SIZE = 1u << 24;  // 16 MiB
  if (payload_len > MAX_WS_FRAME_SIZE) {
    return Status::Error("Type3WebSocket: WS frame exceeds 16 MiB limit");
  }

  if (available < header_len + payload_len) {
    return BufferSlice();  // incomplete frame
  }

  // Consume header
  input_->advance(header_len);

  // Consume payload
  BufferSlice payload = input_->cut_head(static_cast<size_t>(payload_len)).move_as_buffer_slice();

  // Unmask if server→client frame is masked (shouldn't be per RFC, but handle gracefully)
  if (masked) {
    const uint8 *mk = reinterpret_cast<const uint8 *>(hdr.data() + (header_len - 4));
    auto mslice = payload.as_mutable_slice();
    for (size_t i = 0; i < payload.size(); i++) {
      mslice[i] ^= mk[i % 4];
    }
  }

  // Handle control frames
  if (opcode == 0x8) {
    // Close frame
    ws_closed_ = true;
    return BufferSlice();
  }
  if (opcode == 0x9) {
    // Ping → send Pong (opcode 0xA) with echoed payload, masked (client→server)
    string pong_hdr;
    pong_hdr += '\x8A';  // FIN + pong opcode
    size_t plen = payload.size();
    if (plen <= 125) {
      pong_hdr += static_cast<char>(0x80 | plen);
    } else {
      pong_hdr += '\xFE';
      pong_hdr += static_cast<char>((plen >> 8) & 0xFF);
      pong_hdr += static_cast<char>(plen & 0xFF);
    }
    uint8 pmask[4];
    Random::secure_bytes(MutableSlice(reinterpret_cast<char *>(pmask), 4));
    pong_hdr += static_cast<char>(pmask[0]);
    pong_hdr += static_cast<char>(pmask[1]);
    pong_hdr += static_cast<char>(pmask[2]);
    pong_hdr += static_cast<char>(pmask[3]);
    output_->append(pong_hdr);
    // masked pong payload
    string mp(plen, '\0');
    const auto *pp = reinterpret_cast<const uint8 *>(payload.as_slice().data());
    for (size_t i = 0; i < plen; i++) {
      mp[i] = static_cast<char>(pp[i] ^ pmask[i % 4]);
    }
    output_->append(mp);
    return BufferSlice();  // no data for caller
  }
  if (opcode != 0x2 && opcode != 0x0) {
    // Unexpected opcode (text frame etc.) — ignore
    return BufferSlice();
  }

  return payload;
}

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
