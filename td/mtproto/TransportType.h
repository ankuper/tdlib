//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "td/mtproto/ProxySecret.h"

#include "td/utils/common.h"

namespace td {
namespace mtproto {

struct TransportType {
  // === TYPE3-PROXY BEGIN ===
  // HttpStreamType3 = Type3 transport via libteleproto3 t3_client_* (HTTP-stream).
  // WebSocket transport is dead and intentionally not represented.
  enum Type { Tcp, ObfuscatedTcp, Http, HttpStreamType3 } type = Tcp;
  // === TYPE3-PROXY END ===
  int16 dc_id{0};
  ProxySecret secret;
  // === TYPE3-PROXY BEGIN ===
  string host;  // HTTP stream mode: Host header value
  string path;  // HTTP stream mode: POST target path
  // === TYPE3-PROXY END ===

  TransportType() = default;
  TransportType(Type type, int16 dc_id, ProxySecret secret) : type(type), dc_id(dc_id), secret(std::move(secret)) {
  }
  // === TYPE3-PROXY BEGIN ===
  TransportType(Type type, int16 dc_id, ProxySecret secret, string host, string path)
      : type(type), dc_id(dc_id), secret(std::move(secret)), host(std::move(host)), path(std::move(path)) {
  }
  // === TYPE3-PROXY END ===
};

}  // namespace mtproto
}  // namespace td
