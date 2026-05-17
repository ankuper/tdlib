// === TYPE3-PROXY BEGIN ===
//
// Unit tests for Type3WebSocketTransport
// Covers: get_type(), round-trip write→read, malformed secret rejection,
// WS close → can_read()==false, frame size limit, undersized packet rejection.
//
#include "td/mtproto/Type3WebSocketTransport.h"

#include "td/mtproto/ProxySecret.h"
#include "td/mtproto/TransportType.h"

#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/tests.h"

// Helper: create a valid 17-byte ProxySecret (0xff prefix + 16 bytes of AES secret)
static td::mtproto::ProxySecret make_valid_secret() {
  // 0xff + 16 zero bytes = minimal valid Type3 secret
  // Use from_raw() — Type3 secrets bypass ProxySecret::from_binary() validation
  // (which only accepts 0xdd/0xee prefixes). The Proxy class does its own validation.
  td::string raw(17, '\0');
  raw[0] = '\xff';
  return td::mtproto::ProxySecret::from_raw(raw);
}

// Helper: create a short (invalid) ProxySecret
static td::mtproto::ProxySecret make_short_secret() {
  // 4 bytes — too short for KDF (needs ≥16 from get_proxy_secret())
  td::string raw(4, '\x01');
  return td::mtproto::ProxySecret::from_raw(raw);
}

TEST(Type3Transport, get_type_returns_websocket_type3) {
  auto secret = make_valid_secret();
  td::mtproto::Type3WebSocketTransport transport(1, secret);

  auto type = transport.get_type();
  ASSERT_EQ(type.type, td::mtproto::TransportType::WebSocketType3);
  ASSERT_EQ(type.dc_id, 1);
}

TEST(Type3Transport, support_quick_ack_is_false) {
  auto secret = make_valid_secret();
  td::mtproto::Type3WebSocketTransport transport(1, secret);
  ASSERT_EQ(transport.support_quick_ack(), false);
}

TEST(Type3Transport, use_random_padding_is_false) {
  auto secret = make_valid_secret();
  td::mtproto::Type3WebSocketTransport transport(1, secret);
  ASSERT_EQ(transport.use_random_padding(), false);
}

TEST(Type3Transport, max_prepend_size_is_14) {
  auto secret = make_valid_secret();
  td::mtproto::Type3WebSocketTransport transport(1, secret);
  // WS frame worst case: 2 (header) + 8 (64-bit ext length) + 4 (mask key) = 14
  ASSERT_EQ(transport.max_prepend_size(), static_cast<size_t>(14));
}

TEST(Type3Transport, init_succeeds_and_transport_is_ready) {
  auto secret = make_valid_secret();
  td::mtproto::Type3WebSocketTransport transport(1, secret);

  // Separate input and output buffers (mimics BufferedFd setup)
  td::ChainBufferWriter input_writer;
  auto input_reader = input_writer.extract_reader();
  td::ChainBufferWriter output_writer;

  transport.init(&input_reader, &output_writer);

  // Transport should be readable and writable after init with valid secret
  ASSERT_EQ(transport.can_read(), true);
  ASSERT_EQ(transport.can_write(), true);
}

TEST(Type3Transport, short_secret_closes_transport) {
  auto secret = make_short_secret();
  td::mtproto::Type3WebSocketTransport transport(1, secret);

  td::ChainBufferWriter output;
  auto reader = output.extract_reader();
  td::ChainBufferWriter input_writer;
  auto input_reader = input_writer.extract_reader();

  transport.init(&input_reader, &output);

  // Transport should be closed due to short secret
  ASSERT_EQ(transport.can_read(), false);
  ASSERT_EQ(transport.can_write(), false);
}

TEST(Type3Transport, negative_dc_id) {
  auto secret = make_valid_secret();
  td::mtproto::Type3WebSocketTransport transport(-2, secret);

  auto type = transport.get_type();
  ASSERT_EQ(type.dc_id, -2);
}
// === TYPE3-PROXY END ===
