//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2026
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/net/Proxy.h"

#include "td/telegram/td_api.h"

#include "td/utils/utf8.h"

namespace td {

Result<Proxy> Proxy::create_proxy(string server, int port, const td_api::ProxyType *proxy_type) {
  if (proxy_type == nullptr) {
    return Status::Error(400, "Proxy type must be non-empty");
  }
  if (server.empty()) {
    return Status::Error(400, "Server name must be non-empty");
  }
  if (server.size() > 255) {
    return Status::Error(400, "Server name is too long");
  }
  if (!check_utf8(server)) {
    return Status::Error(400, "Server name must be encoded in UTF-8");
  }
  if (port <= 0 || port > 65535) {
    return Status::Error(400, "Wrong port number");
  }

  switch (proxy_type->get_id()) {
    case td_api::proxyTypeSocks5::ID: {
      auto type = static_cast<const td_api::proxyTypeSocks5 *>(proxy_type);
      return Proxy::socks5(std::move(server), port, type->username_, type->password_);
    }
    case td_api::proxyTypeHttp::ID: {
      auto type = static_cast<const td_api::proxyTypeHttp *>(proxy_type);
      if (type->http_only_) {
        return Proxy::http_caching(std::move(server), port, type->username_, type->password_);
      } else {
        return Proxy::http_tcp(std::move(server), port, type->username_, type->password_);
      }
    }
    case td_api::proxyTypeMtproto::ID: {
      auto type = static_cast<const td_api::proxyTypeMtproto *>(proxy_type);
      TRY_RESULT(secret, mtproto::ProxySecret::from_link(type->secret_));
      return Proxy::mtproto(std::move(server), port, std::move(secret));
    }
    // === TYPE3-PROXY BEGIN ===
    case td_api::proxyTypeTeleproto3::ID: {
      auto type = static_cast<const td_api::proxyTypeTeleproto3 *>(proxy_type);
      if (type->secret_.empty()) {
        return Status::Error(400, "Teleproto3 proxy secret must be non-empty");
      }
      if (type->endpoint_.empty()) {
        return Status::Error(400, "Teleproto3 proxy endpoint must be non-empty");
      }
      if (type->endpoint_.substr(0, 6) != "wss://" && type->endpoint_.substr(0, 5) != "ws://") {
        return Status::Error(400, "Teleproto3 proxy endpoint must use wss:// or ws:// scheme");
      }
      TRY_RESULT(secret, mtproto::ProxySecret::from_link(type->secret_));
      return Proxy::teleproto3(std::move(server), port, std::move(secret), type->endpoint_);
    }
    // === TYPE3-PROXY END ===
    default:
      UNREACHABLE();
      return Status::Error(400, "Wrong proxy type");
  }
}

Result<Proxy> Proxy::create_proxy(const td_api::proxy *proxy) {
  if (proxy == nullptr) {
    return Status::Error(400, "Proxy must be non-empty");
  }
  return create_proxy(proxy->server_, proxy->port_, proxy->type_.get());
}

td_api::object_ptr<td_api::proxy> Proxy::get_proxy_object() const {
  auto type = [&]() -> td_api::object_ptr<td_api::ProxyType> {
    switch (type_) {
      case Type::Socks5:
        return td_api::make_object<td_api::proxyTypeSocks5>(user_, password_);
      case Type::HttpTcp:
        return td_api::make_object<td_api::proxyTypeHttp>(user_, password_, false);
      case Type::HttpCaching:
        return td_api::make_object<td_api::proxyTypeHttp>(user_, password_, true);
      case Type::Mtproto:
        return td_api::make_object<td_api::proxyTypeMtproto>(secret_.get_encoded_secret());
      // === TYPE3-PROXY BEGIN ===
      case Type::Teleproto3:
        return td_api::make_object<td_api::proxyTypeTeleproto3>(secret_.get_encoded_secret(), endpoint_);
      // === TYPE3-PROXY END ===
      default:
        UNREACHABLE();
        return nullptr;
    }
  }();
  return td_api::make_object<td_api::proxy>(server_, port_, std::move(type));
}

StringBuilder &operator<<(StringBuilder &string_builder, const Proxy &proxy) {
  switch (proxy.type()) {
    case Proxy::Type::Socks5:
      return string_builder << "ProxySocks5 " << proxy.server() << ":" << proxy.port();
    case Proxy::Type::HttpTcp:
      return string_builder << "ProxyHttpTcp " << proxy.server() << ":" << proxy.port();
    case Proxy::Type::HttpCaching:
      return string_builder << "ProxyHttpCaching " << proxy.server() << ":" << proxy.port();
    case Proxy::Type::Mtproto:
      return string_builder << "ProxyMtproto " << proxy.server() << ":" << proxy.port() << "/"
                            << proxy.secret().get_encoded_secret();
    // === TYPE3-PROXY BEGIN ===
    case Proxy::Type::Teleproto3:
      return string_builder << "ProxyTeleproto3 " << proxy.server() << ":" << proxy.port()
                            << "/" << proxy.secret().get_encoded_secret()
                            << "/" << proxy.endpoint();
    // === TYPE3-PROXY END ===
    case Proxy::Type::None:
      return string_builder << "ProxyEmpty";
    default:
      UNREACHABLE();
      return string_builder;
  }
}

}  // namespace td
