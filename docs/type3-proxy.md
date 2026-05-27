# Type3 Proxy Support

This fork of TDLib adds native support for the [Type3 (teleproto3)](https://github.com/ankuper/teleproto3) censorship-resistant transport. Type3 tunnels MTProto traffic over standard HTTPS connections — either WebSocket or HTTP POST with chunked encoding — to bypass DPI-based blocking.

## Transport Modes

| Mode | Endpoint URL | Description |
|------|-------------|-------------|
| **WebSocket** | `wss://host/path` | RFC 6455 WebSocket upgrade, binary frames carry obfuscated-2 MTProto |
| **HTTP stream** | `https://host/path` | HTTP POST + `Transfer-Encoding: chunked`, looks like a REST API call |

Both modes use the same underlying crypto (AES-256-CTR obfuscated-2 with HMAC-derived keys) and Session Header. The transport mode is selected by the endpoint URL scheme.

## Architecture

```
TDLib Client
  └── Session (td/telegram/net/Session.cpp)
        └── RawConnection (td/mtproto/RawConnection.cpp)
              └── TlsPipeline (TLS 1.2/1.3)
                    └── Transport (IStreamTransport)
                          ├── Type3WebSocketTransport.cpp  (wss://)
                          └── Type3HttpStreamTransport.cpp (https://)
                                └── libteleproto3 (obfs2 KDF + AES-CTR)
```

### Key files

| File | Purpose |
|------|---------|
| `td/mtproto/Type3WebSocketTransport.h/cpp` | WebSocket transport: WS frame parse/write + obfs2 |
| `td/mtproto/Type3HttpStreamTransport.h/cpp` | HTTP stream transport: chunked framing + obfs2 |
| `td/mtproto/RawConnection.cpp` | TLS pipeline integration, multi-pump read loop |
| `td/telegram/net/ConnectionCreator.cpp` | Proxy dispatch: `WebSocketType3Proxy` / `HttpStreamType3Proxy` |
| `td/telegram/net/Session.cpp` | Session management, Type3 connection lifecycle |

## Client Configuration

### TDLib JSON API

```json
{
  "@type": "addProxy",
  "server": "proxy.example.com",
  "port": 443,
  "enable": true,
  "type": {
    "@type": "proxyTypeMtproto",
    "secret": "fff5c64bc3e21530a2a8a60ea82214ed4770726f78792e6578616d706c652e636f6d2f77732f613366376332"
  }
}
```

The `secret` field is the Type3 secret in hex: `ff` marker + 16-byte key + host/path encoded as UTF-8 hex.

### Endpoint selection

The transport mode is determined by the endpoint URL in the client configuration:

- **No explicit endpoint**: defaults to `wss://<host>/v1/api/mtpr`
- **`endpoint=wss://host/path`**: WebSocket mode
- **`endpoint=https://host/path`**: HTTP stream mode

### Python tg-client example

```json
{
  "proxy": {
    "type3": true,
    "host": "94.156.131.252",
    "port": 443,
    "secret": "f5c64bc3e21530a2a8a60ea82214ed47",
    "endpoint": "wss://arctic-breeze.my.id:443/v1/api/mtpr"
  }
}
```

## Building

This fork requires the [libteleproto3](https://github.com/ankuper/teleproto3) library source tree to be available at build time. Set `TELEPROTO3_SRC_DIR` to point to the `lib/` directory:

```bash
cd tdlib
mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DTELEPROTO3_SRC_DIR=/path/to/teleproto3/lib
cmake --build . --target tdjson -j$(nproc)
```

The build produces `libtdjson.so` (or `.dylib`) with Type3 transport support compiled in.

## Server-Side Requirements

The Type3 server ([teleproxy](https://github.com/ankuper/teleproxy)) runs behind an nginx reverse proxy. For HTTP stream mode, nginx must be configured with:

- `proxy_buffering off` + `proxy_request_buffering off`
- `ssl_buffer_size 4k` (prevents TLS record coalescing that stalls response headers)
- `proxy_read_timeout 86400s` (long-lived sessions)

See [teleproto3 spec §1.4](https://github.com/ankuper/teleproto3/blob/main/spec/wire-format.md) for the full nginx configuration reference.

## Debug Logging

Type3 diagnostic logs are available at TDLib verbosity level 2+ (`VLOG(dc)`):

| Prefix | Content |
|--------|---------|
| `T3_READ` | Socket receive: bytes received, plaintext available |
| `T3_WRITE` | Socket send: bytes sent |
| `T3_CRYPTO` | MTProto crypto layer: bytes written to transport |
| `T3_DEBUG` | Transport init: key derivation, header dumps |
| `T3_HTTP_PARSE` | HTTP stream: response header parsing |
| `T3_SESSION` | Session: query dispatch |
| `T3_STALL` | Session: connection not ready (diagnostics) |

Set verbosity with:
```json
{"@type": "setLogVerbosityLevel", "new_verbosity_level": 2}
```

## Protocol Specification

- [teleproto3 spec](https://github.com/ankuper/teleproto3/blob/main/spec/wire-format.md) — normative wire format
- [teleproto3 README](https://github.com/ankuper/teleproto3) — protocol overview
- [teleproxy HTTP stream docs](https://github.com/ankuper/teleproxy/blob/teleproto3-support/docs/features/http-stream-transport.md) — server deployment
