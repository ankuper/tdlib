// === TYPE3-PROXY BEGIN ===
//
// Smoke test for proxyTypeTeleproto3 TL schema addition.
// Verifies that the TL-generated class is well-formed and linkable.
//
#include "td/telegram/td_api.h"

#include "td/utils/common.h"
#include "td/utils/tests.h"

TEST(Type3Schema, instantiate_and_access_fields) {
  auto proxy = td::td_api::proxyTypeTeleproto3(
      "ff000000000000000000000000000000006578616d706c652e636f6d2f7773",
      "wss://example.com/ws");

  ASSERT_EQ(proxy.secret_, "ff000000000000000000000000000000006578616d706c652e636f6d2f7773");
  ASSERT_EQ(proxy.endpoint_, "wss://example.com/ws");
}

TEST(Type3Schema, get_id_is_unique) {
  auto id_teleproto3 = td::td_api::proxyTypeTeleproto3::ID;
  auto id_mtproto = td::td_api::proxyTypeMtproto::ID;
  auto id_socks5 = td::td_api::proxyTypeSocks5::ID;
  auto id_http = td::td_api::proxyTypeHttp::ID;

  // All four proxy type IDs must be non-zero and mutually distinct
  ASSERT_TRUE(id_teleproto3 != 0);
  ASSERT_TRUE(id_teleproto3 != id_mtproto);
  ASSERT_TRUE(id_teleproto3 != id_socks5);
  ASSERT_TRUE(id_teleproto3 != id_http);
}

TEST(Type3Schema, default_constructor) {
  td::td_api::proxyTypeTeleproto3 proxy;

  // Default-constructed strings should be empty
  ASSERT_EQ(proxy.secret_, "");
  ASSERT_EQ(proxy.endpoint_, "");
  // ID is accessible as a public static const; get_id() is private virtual
  ASSERT_TRUE(td::td_api::proxyTypeTeleproto3::ID != 0);
}
// === TYPE3-PROXY END ===

