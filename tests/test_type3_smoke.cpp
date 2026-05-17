// === TYPE3-PROXY BEGIN ===
// tests/test_type3_smoke.cpp — AR Story 10-5: smoke test for Type3 proxy support.
//
// Strategy:
//   1. Compile-time: static_assert verifies proxyTypeTeleproto3::ID == 600379549
//   2. Runtime: td_json_client_create + td_json_client_execute(testCallString)
//      proves libtdjson.so links and loads correctly.
//
// Compile (note: source file BEFORE -l flag on Linux):
//   g++ -std=c++17 -I/usr/local/include test.cpp -L/usr/local/lib -ltdjson -o test
// === TYPE3-PROXY END ===

#include <td/telegram/td_api.h>
#include <td/telegram/td_json_client.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

int main() {
    // ── Compile-time check ─────────────────────────────────────────────────
    static_assert(td::td_api::proxyTypeTeleproto3::ID == 600379549,
                  "proxyTypeTeleproto3::ID must equal CRC32 600379549");

    // ── Runtime check via JSON API ─────────────────────────────────────────
    void *client = td_json_client_create();
    assert(client != nullptr && "td_json_client_create() must return non-null");

    // testCallString is synchronous and echoes back as testString
    const char *req = "{\"@type\":\"testCallString\",\"x\":\"t3ok\"}";
    const char *result = td_json_client_execute(client, req);
    assert(result != nullptr && "td_json_client_execute must return non-null");

    std::string res(result);
    std::cout << "JSON API response: " << res << std::endl;

    // testCallString returns {"@type":"testString","value":"t3ok"}
    assert(res.find("t3ok") != std::string::npos
           && "testCallString must echo input in testString response");

    td_json_client_destroy(client);

    std::cout << "Type3 smoke test PASSED" << std::endl;
    std::cout << "  static_assert: proxyTypeTeleproto3::ID == 600379549 OK" << std::endl;
    std::cout << "  td_json_client: create/execute/destroy OK" << std::endl;
    return 0;
}
