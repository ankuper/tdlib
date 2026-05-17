// === TYPE3-PROXY BEGIN ===
// tests/test_type3_smoke.cpp — AR Story 10-5: smoke test for Type3 proxy support.
//
// Validates:
//   1. Compile-time: static_assert proxyTypeTeleproto3::ID == 600379549
//   2. Runtime: td_json_client_execute with getTextEntities (synchronous method)
//      proves libtdjson.so links, loads, and the JSON dispatcher works.
//
// Compile (source before -l on Linux):
//   g++ -std=c++17 -I/usr/local/include test.cpp -L/usr/local/lib -ltdjson -o test
// === TYPE3-PROXY END ===

#include <td/telegram/td_api.h>
#include <td/telegram/td_json_client.h>
#include <cassert>
#include <iostream>
#include <string>

int main() {
    // ── Compile-time: verify CRC32 constructor ID ──────────────────────────
    static_assert(td::td_api::proxyTypeTeleproto3::ID == 600379549,
                  "proxyTypeTeleproto3::ID must equal CRC32 600379549");

    // ── Runtime: JSON API via synchronous td_json_client_execute ───────────
    // getTextEntities is one of the few methods that works synchronously.
    const char *req = "{\"@type\":\"getTextEntities\",\"text\":\"@type3test\"}";
    const char *result = td_json_client_execute(nullptr, req);
    assert(result != nullptr && "td_json_client_execute must return non-null");

    std::string res(result);
    std::cout << "JSON response: " << res << std::endl;

    // getTextEntities returns {"@type":"textEntities","entities":[...]}
    assert(res.find("textEntities") != std::string::npos
           && "getTextEntities must return textEntities response");

    std::cout << "Type3 smoke test PASSED" << std::endl;
    std::cout << "  static_assert: proxyTypeTeleproto3::ID == 600379549 OK" << std::endl;
    std::cout << "  td_json_client_execute(getTextEntities): OK" << std::endl;
    std::cout << "  libtdjson.so: linked and loaded OK" << std::endl;
    return 0;
}
