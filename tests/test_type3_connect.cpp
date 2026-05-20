/**
 * test_type3_connect.cpp — Local smoke test for Type3 WebSocket proxy.
 *
 * Uses libtdjson JSON API to connect to Telegram through the Type3 WebSocket
 * proxy via nginx at 94.156.131.252:8080 → teleproxy:3130.
 *
 * Build (macOS):
 *   cd /Volumes/BuildCache/tdlib/build
 *   clang++ -std=c++17 -I.. -o test_type3_connect \
 *       ../tests/test_type3_connect.cpp -L. -ltdjson -Wl,-rpath,@loader_path/.
 *
 * Run:
 *   cd /Volumes/BuildCache/tdlib/build && ./test_type3_connect
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// Use the C API directly via extern "C"
extern "C" {
    void* td_json_client_create();
    void  td_json_client_send(void* client, const char* request);
    const char* td_json_client_receive(void* client, double timeout);
    void  td_json_client_destroy(void* client);
    const char* td_json_client_execute(void* client, const char* request);
}

int main() {
    // Set verbosity to 4 for detailed transport logs
    td_json_client_execute(nullptr,
        "{\"@type\":\"setLogVerbosityLevel\",\"new_verbosity_level\":4}");

    printf("=== Type3 WebSocket Proxy Test (Local) ===\n");

    // Clean up old DB to force fresh start
    system("rm -rf /tmp/tdlib_type3_test");

    void* client = td_json_client_create();
    printf("TDLib client created\n");

    // 1. Set TDLib parameters
    td_json_client_send(client,
        "{"
        "\"@type\":\"setTdlibParameters\","
        "\"database_directory\":\"/tmp/tdlib_type3_test\","
        "\"use_message_database\":false,"
        "\"use_secret_chats\":false,"
        "\"api_id\":94575,"
        "\"api_hash\":\"a3406de8d171bb422bb6ddf3bbd800e2\","
        "\"system_language_code\":\"en\","
        "\"device_model\":\"Type3Test\","
        "\"application_version\":\"1.0\","
        "\"use_test_dc\":false"
        "}");
    printf("Sent setTdlibParameters\n");

    // 2. Add the Teleproto3 proxy
    // server:port = TCP endpoint for the connection (nginx TLS terminator)
    // endpoint = wss:// URL used for WS upgrade (Host header + path)
    // secret = MTProxy secret (16-byte hex)
    const char* add_proxy =
        "{"
        "\"@type\":\"addProxy\","
        "\"proxy\":{"
            "\"@type\":\"proxy\","
            "\"server\":\"94.156.131.252\","
            "\"port\":443,"
            "\"type\":{"
                "\"@type\":\"proxyTypeTeleproto3\","
                "\"secret\":\"78ef151a20066770db00a2f905c103e9\","
                "\"endpoint\":\"wss://arctic-breeze.my.id:443/ws/7f34ba\""
            "}"
        "},"
        "\"enable\":true"
        "}";
    td_json_client_send(client, add_proxy);
    printf("Sent addProxy (proxyTypeTeleproto3) -> wss://arctic-breeze.my.id:443\n");

    // 3. Poll for updates for 30 seconds
    printf("Polling for updates (30s)...\n");
    int connected = 0;
    for (int i = 0; i < 300; i++) {
        const char* resp = td_json_client_receive(client, 0.1);
        if (resp) {
            // Print connection-relevant responses
            if (strstr(resp, "authorizationState") ||
                strstr(resp, "connectionState") ||
                strstr(resp, "error") ||
                strstr(resp, "proxy") ||
                strstr(resp, "updateOption")) {
                printf("[%5.1fs] %s\n", i * 0.1, resp);
            }
            if (strstr(resp, "connectionStateReady")) {
                printf("\n*** SUCCESS: Connection established! ***\n");
                connected = 1;
                break;
            }
        }
    }

    if (!connected) {
        printf("\n*** TIMEOUT: Connection not established after 30s ***\n");
    }

    printf("Destroying client.\n");
    td_json_client_destroy(client);
    return connected ? 0 : 1;
}
