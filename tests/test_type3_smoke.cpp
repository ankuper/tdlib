// === TYPE3-PROXY BEGIN ===
// tests/test_type3_smoke.cpp — AR Story 10-5: smoke test for proxyTypeTeleproto3 class.
// Verifies that:
//   (1) The generated td_api::proxyTypeTeleproto3 class can be instantiated.
//   (2) Both secret_ and endpoint_ fields are non-empty after construction.
//   (3) The public static ID constant equals the expected CRC32 constructor ID (600379549).
//   (4) The binary links and runs successfully against libtdjson.so.
//
// Compile:
//   g++ -std=c++17 -I/usr/local/include -L/usr/local/lib -ltdjson \
//       tests/test_type3_smoke.cpp -o test_type3_smoke
// Run (inside Docker runtime image — after ldconfig has been run):
//   ./test_type3_smoke
// === TYPE3-PROXY END ===

#include <td/telegram/td_api.h>
#include <cassert>
#include <iostream>
#include <string>

int main() {
    // Instantiate proxyTypeTeleproto3 with a realistic ff-prefixed secret and WSS endpoint.
    auto proxy = td::td_api::make_object<td::td_api::proxyTypeTeleproto3>(
        "ff0011aabbccddeeff0011aabbccddeeff", "wss://arctic-breeze.my.id/ws");

    // AC #5: verify secret_ field is populated
    assert(!proxy->secret_.empty() && "secret_ must not be empty");

    // AC #5: verify endpoint_ field is populated
    assert(!proxy->endpoint_.empty() && "endpoint_ must not be empty");

    // AC #5: verify ID static constant equals expected CRC32 constructor ID.
    // Note: get_id() is private in TDLib generated code; the public API is the static ID constant.
    // CRC32 ID 600379549 verified during Story 10-1 adversarial review.
    static_assert(td::td_api::proxyTypeTeleproto3::ID == 600379549,
                  "proxyTypeTeleproto3::ID must equal CRC32 600379549 from Story 10-1");

    // Verify exact field values for deterministic testing
    assert(proxy->secret_ == "ff0011aabbccddeeff0011aabbccddeeff");
    assert(proxy->endpoint_ == "wss://arctic-breeze.my.id/ws");

    std::cout << "Type3 smoke test PASSED" << std::endl;
    std::cout << "  secret:   " << proxy->secret_ << std::endl;
    std::cout << "  endpoint: " << proxy->endpoint_ << std::endl;
    std::cout << "  ID:       " << td::td_api::proxyTypeTeleproto3::ID << std::endl;
    return 0;
}
