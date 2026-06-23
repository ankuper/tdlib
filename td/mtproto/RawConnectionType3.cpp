// === TYPE3-PROXY BEGIN ===
//
// RawConnectionType3 — implementation. See header for the architecture.
//
#include "td/mtproto/RawConnectionType3.h"

#include "td/mtproto/AuthKey.h"
#include "td/mtproto/PacketInfo.h"
#include "td/mtproto/Transport.h"

#include "td/utils/buffer.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include "td/utils/port/detail/NativeFd.h"
#include "td/utils/port/detail/PollableFd.h"
#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"

// libteleproto3 canonical client transport API — the ONE source of truth for
// the Type3 wire format. No protocol is re-implemented in this file.
#include "t3_client.h"

#include <utility>

namespace td {
namespace mtproto {

namespace {

// READ_BUFFER_SIZE analogue: largest MTProto packet we accept (matches the
// MAX_PACKET_SIZE guard used by RawConnectionDefault).
constexpr size_t MAX_PACKET_SIZE = (1 << 22) + 1024;

class RawConnectionType3 final : public RawConnection {
 public:
  RawConnectionType3(IPAddress ip_address, t3_client_stream *stream, td::NativeFd native_fd,
                     unique_ptr<StatsCallback> stats_callback)
      : ip_address_(std::move(ip_address))
      , stream_(stream)
      , poll_info_(std::move(native_fd))
      , stats_callback_(std::move(stats_callback)) {
    LOG(DEBUG) << "Create Type3 raw connection " << this;
  }

  RawConnectionType3(const RawConnectionType3 &) = delete;
  RawConnectionType3 &operator=(const RawConnectionType3 &) = delete;

  ~RawConnectionType3() final {
    close();
  }

  void set_connection_token(ConnectionManager::ConnectionToken connection_token) final {
    connection_token_ = std::move(connection_token);
  }

  bool can_send() const final {
    return !closed_;
  }

  TransportType get_transport_type() const final {
    return TransportType{TransportType::HttpStreamType3, dc_id_, secret_, host_, path_};
  }

  size_t send_crypto(const Storer &storer, uint64 session_id, int64 salt, const AuthKey &auth_key,
                     uint64 quick_ack_token) final {
    PacketInfo packet_info;
    packet_info.version = 2;
    packet_info.no_crypto_flag = false;
    packet_info.salt = salt;
    packet_info.session_id = session_id;
    // libteleproto3 handles its own intermediate-format framing + padding, so the
    // MTProto layer must not add random padding (matches Android: raw MTProto in,
    // raw MTProto out — the transport layer owns padding/jitter).
    packet_info.use_random_padding = false;

    // quick-ack is not supported by the Type3 transport (no support_quick_ack()).
    auto packet = Transport::write(storer, auth_key, &packet_info);
    auto packet_size = packet.size();
    queue_write(packet.as_slice());
    return packet_size;
  }

  void send_no_crypto(const Storer &storer) final {
    PacketInfo packet_info;
    packet_info.no_crypto_flag = true;
    auto packet = Transport::write(storer, AuthKey(), &packet_info);
    LOG(INFO) << "Send Type3 handshake packet: " << format::as_hex_dump<4>(packet.as_slice());
    queue_write(packet.as_slice());
  }

  PollableFdInfo &get_poll_info() final {
    return poll_info_;
  }

  StatsCallback *stats_callback() final {
    return stats_callback_.get();
  }

  // NB: After first returned error, all subsequent calls will return error too.
  Status flush(const AuthKey &auth_key, Callback &callback) final {
    auto status = do_flush(auth_key, callback);
    if (status.is_error()) {
      if (stats_callback_ && status.code() != 2) {
        stats_callback_->on_error();
      }
      has_error_ = true;
    }
    return status;
  }

  bool has_error() const final {
    return has_error_;
  }

  void close() final {
    if (closed_) {
      return;
    }
    LOG(DEBUG) << "Close Type3 raw connection " << this;
    closed_ = true;
    // Hand the fd back to libteleproto3 as the sole owner before destroy:
    //  - the scheduler must have already unsubscribed (it owns the PollableFd
    //    via get_poll_info().extract_pollable_fd / get_pollable_fd_ref);
    //  - release() detaches the fd from our NativeFd so we do NOT ::close() it;
    //  - t3_client_destroy() closes the fd and frees the stream.
    if (!poll_info_.empty()) {
      poll_info_.move_as_native_fd().release();
    }
    if (stream_ != nullptr) {
      t3_client_destroy(stream_);
      stream_ = nullptr;
    }
  }

  PublicFields &extra() final {
    return extra_;
  }
  const PublicFields &extra() const final {
    return extra_;
  }

  // Stash the Type3 descriptors so get_transport_type() can report them.
  void set_descriptors(int16 dc_id, ProxySecret secret, string host, string path) {
    dc_id_ = dc_id;
    secret_ = std::move(secret);
    host_ = std::move(host);
    path_ = std::move(path);
  }

 private:
  PublicFields extra_;
  IPAddress ip_address_;

  t3_client_stream *stream_{nullptr};
  PollableFdInfo poll_info_;
  bool closed_{false};
  bool has_error_{false};
  bool ready_seen_{false};

  // Reusable destination for t3_client_read (sized for the largest legal packet).
  BufferSlice read_scratch_;

  // Outgoing MTProto bytes waiting until the stream is READY / send buffer drains.
  ChainBufferWriter pending_write_;
  ChainBufferReader pending_read_ = pending_write_.extract_reader();

  unique_ptr<StatsCallback> stats_callback_;
  ConnectionManager::ConnectionToken connection_token_;

  // Descriptors reported by get_transport_type() (purely informational).
  int16 dc_id_{0};
  ProxySecret secret_;
  string host_;
  string path_;

  void queue_write(Slice bytes) {
    pending_write_.append(bytes);
  }

  void on_read(size_t size, Callback &callback) {
    if (size == 0) {
      return;
    }
    if (stats_callback_) {
      stats_callback_->on_read(size);
    }
    callback.on_read(size);
  }

  // Drive the t3_client_* state machine and move MTProto packets in both
  // directions. Mirrors RawConnectionDefault::do_flush but with libteleproto3
  // as the transport instead of BufferedFd + IStreamTransport.
  Status do_flush(const AuthKey &auth_key, Callback &callback) TD_WARN_UNUSED_RESULT {
    if (has_error_) {
      return Status::Error("Connection has already failed");
    }
    if (closed_ || stream_ == nullptr) {
      return Status::Error("Type3 connection closed");
    }

    // Consume the kernel readiness flags the poll surfaced for our fd.
    poll_info_.sync_with_poll();

    // Pump the transport state machine (TCP connect → TLS → obfs2 handshake).
    t3_result_t pump_rc = t3_client_pump(stream_);
    (void)pump_rc;  // BUF_TOO_SMALL just means "keep polling"
    auto state = t3_client_get_state(stream_);
    if (state == T3_CLIENT_STATE_ERROR) {
      return Status::Error(PSLICE() << "Type3 transport error: " << t3_client_last_error(stream_));
    }
    if (state == T3_CLIENT_STATE_CLOSED) {
      return Status::Error("Type3 transport closed");
    }
    if (state != T3_CLIENT_STATE_READY) {
      // Still handshaking — nothing to read/write yet. Keep POLLOUT armed so we
      // get woken to pump again.
      poll_info_.add_flags(PollFlags::Write());
      return Status::OK();
    }
    if (!ready_seen_) {
      ready_seen_ = true;
      LOG(DEBUG) << "Type3 raw connection " << this << " READY";
      if (stats_callback_) {
        stats_callback_->on_pong();
      }
    }

    TRY_STATUS(flush_read(auth_key, callback));
    TRY_STATUS(callback.before_write());
    TRY_STATUS(flush_write());
    return Status::OK();
  }

  Status flush_read(const AuthKey &auth_key, Callback &callback) {
    while (true) {
      // libteleproto3 hands us a *complete bare MTProto packet* (it strips its
      // own intermediate-format length prefix + AES-CTR + chunk framing). That
      // is exactly what Transport::read() expects. Read into a reusable scratch
      // sized for the largest legal packet, then hand an exact-sized BufferSlice
      // to the MTProto layer (the callback may retain it).
      if (read_scratch_.empty()) {
        read_scratch_ = BufferSlice(MAX_PACKET_SIZE);
      }
      size_t out_len = 0;
      t3_result_t rc =
          t3_client_read(stream_, read_scratch_.as_mutable_slice().ubegin(), read_scratch_.size(), &out_len);
      if (rc == T3_ERR_BUF_TOO_SMALL || out_len == 0) {
        break;  // no complete packet available yet
      }
      if (rc != T3_OK) {
        return Status::Error(PSLICE() << "Type3 read error: " << t3_client_last_error(stream_));
      }
      BufferSlice packet(read_scratch_.as_slice().substr(0, out_len));
      on_read(out_len, callback);

      PacketInfo packet_info;
      packet_info.version = 2;

      TRY_RESULT(read_result, Transport::read(packet.as_mutable_slice(), auth_key, &packet_info));
      switch (read_result.type()) {
        case Transport::ReadResult::Quickack:
          TRY_STATUS(on_quick_ack(read_result.quick_ack(), callback));
          break;
        case Transport::ReadResult::Error:
          TRY_STATUS(on_read_mtproto_error(read_result.error()));
          break;
        case Transport::ReadResult::Packet:
          if (!auth_key.empty()) {
            if (stats_callback_) {
              stats_callback_->on_pong();
            }
          }
          TRY_STATUS(callback.on_raw_packet(packet_info, packet.from_slice(read_result.packet())));
          break;
        case Transport::ReadResult::Nop:
          break;
        default:
          UNREACHABLE();
      }
    }
    return Status::OK();
  }

  Status flush_write() {
    pending_read_.sync_with_writer();
    while (pending_read_.size() > 0) {
      auto src = pending_read_.prepare_read();
      t3_result_t rc = t3_client_write(stream_, src.ubegin(), src.size());
      if (rc == T3_ERR_BUF_TOO_SMALL) {
        // Kernel send buffer full — retry after POLLOUT.
        poll_info_.add_flags(PollFlags::Write());
        break;
      }
      if (rc != T3_OK) {
        return Status::Error(PSLICE() << "Type3 write error: " << t3_client_last_error(stream_));
      }
      // t3_client_write() takes ownership of the whole slice (queues internally),
      // so the bytes are consumed (mirrors the Android outgoingByteStream->discard).
      if (stats_callback_) {
        stats_callback_->on_write(src.size());
      }
      pending_read_.confirm_read(src.size());
    }
    return Status::OK();
  }

  Status on_read_mtproto_error(int32 error_code) {
    if (error_code == -429) {
      if (stats_callback_) {
        stats_callback_->on_mtproto_error();
      }
      return Status::Error(500, PSLICE() << "MTProto error: " << error_code);
    }
    if (error_code == -404) {
      return Status::Error(-404, PSLICE() << "MTProto error: " << error_code);
    }
    return Status::Error(PSLICE() << "MTProto error: " << error_code);
  }

  Status on_quick_ack(uint32 quick_ack, Callback &callback) {
    LOG(WARNING) << "Receive unexpected quick_ack " << quick_ack << " on Type3 connection";
    return Status::OK();
  }
};

}  // namespace

Result<unique_ptr<RawConnection>> create_raw_connection_type3(IPAddress ip_address, string endpoint, UInt128 secret,
                                                              int16 dc_id,
                                                              unique_ptr<RawConnection::StatsCallback> stats_callback) {
  // Parse host/path out of the endpoint purely for get_transport_type() reporting.
  // libteleproto3 re-parses the endpoint itself; this is informational only.
  string host;
  string path;
  {
    Slice ep(endpoint);
    if (ep.substr(0, 8) == "https://") {
      ep = ep.substr(8);
    } else if (ep.substr(0, 7) == "http://") {
      ep = ep.substr(7);
    }
    auto slash = ep.find('/');
    if (slash == Slice::npos) {
      host = ep.str();
    } else {
      host = ep.substr(0, slash).str();
      path = ep.substr(slash + 1).str();
    }
  }

  t3_client_stream *stream = nullptr;
  t3_result_t rc = t3_client_create(endpoint.c_str(), secret.raw, dc_id, &stream);
  if (rc != T3_OK || stream == nullptr) {
    if (stream != nullptr) {
      t3_client_destroy(stream);
    }
    return Status::Error(PSLICE() << "t3_client_create failed for " << endpoint << ": rc=" << static_cast<int>(rc));
  }

  int fd = t3_client_get_fd(stream);
  if (fd < 0) {
    t3_client_destroy(stream);
    return Status::Error("t3_client_get_fd returned -1");
  }

  // Wrap the libteleproto3-owned fd so TDLib's scheduler can poll it. nolog=true
  // and we relinquish ownership via NativeFd::release() in close() — the C
  // library remains the sole owner / closer of the fd.
  td::NativeFd native_fd(static_cast<td::NativeFd::Fd>(fd), /*nolog=*/true);

  auto raw = make_unique<RawConnectionType3>(std::move(ip_address), stream, std::move(native_fd),
                                             std::move(stats_callback));
  raw->set_descriptors(dc_id, ProxySecret::from_raw(Slice(secret.raw, 16).str()), std::move(host), std::move(path));

  // Kick the state machine once so the first POLLOUT/POLLIN makes progress.
  t3_client_pump(stream);
  return std::move(raw);
}

}  // namespace mtproto
}  // namespace td
// === TYPE3-PROXY END ===
