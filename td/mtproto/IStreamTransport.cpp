//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/mtproto/IStreamTransport.h"

#include "td/mtproto/HttpTransport.h"
#include "td/mtproto/TcpTransport.h"
// === TYPE3-PROXY BEGIN ===
#include "td/mtproto/Type3Transport.h"
// === TYPE3-PROXY END ===

namespace td {
namespace mtproto {

unique_ptr<IStreamTransport> create_transport(TransportType type) {
  switch (type.type) {
    case TransportType::ObfuscatedTcp:
      return td::make_unique<tcp::ObfuscatedTransport>(type.dc_id, std::move(type.secret));
    case TransportType::Tcp:
      return td::make_unique<tcp::OldTransport>();
    case TransportType::Http:
      return td::make_unique<http::Transport>(type.secret.get_raw_secret().str());
    // === TYPE3-PROXY BEGIN ===
    case TransportType::WebSocketType3:
      return td::make_unique<Type3Transport>(type.dc_id, std::move(type.secret), Type3Transport::Mode::WebSocket);
    case TransportType::HttpStreamType3:
      return td::make_unique<Type3Transport>(type.dc_id, std::move(type.secret), Type3Transport::Mode::HttpStream,
                                             std::move(type.host), std::move(type.path));
    // === TYPE3-PROXY END ===
  }
  UNREACHABLE();
}

}  // namespace mtproto
}  // namespace td

