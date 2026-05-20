// === TYPE3-PROXY BEGIN ===
//
// TlsPipeline — move-only container for the SslStream ByteFlow pipeline.
//
// Created by WebSocketType3Proxy during wss:// handshake.
// Transferred to RawConnectionDefault via Callback::set_result so that
// TLS encryption/decryption persists for the lifetime of the connection.
//
// Allocated on the heap (unique_ptr<TlsPipeline>) so that internal
// ByteFlow pointers remain valid after ownership transfer.
//
// The pipeline provides:
//   - plaintext_reader():  decrypted data for the transport to read
//   - plaintext_writer():  buffer for the transport to write plaintext into
//   - pump_read():         decrypt ciphertext from socket input → plaintext_reader
//   - pump_write():        encrypt plaintext from plaintext_writer → socket output
//
#pragma once

#include "td/net/SslStream.h"

#include "td/utils/buffer.h"
#include "td/utils/ByteFlow.h"

namespace td {

class TlsPipeline {
 public:
  TlsPipeline() = default;
  TlsPipeline(const TlsPipeline &) = delete;
  TlsPipeline &operator=(const TlsPipeline &) = delete;
  // Move disabled — heap-allocated, transferred via unique_ptr only.
  TlsPipeline(TlsPipeline &&) = delete;
  TlsPipeline &operator=(TlsPipeline &&) = delete;

  SslStream ssl_stream;

  // Application-side write buffer (plaintext → SSL encrypt → socket)
  ChainBufferWriter app_write_buf;
  ChainBufferReader app_write_reader;

  // Read path:  fd_.input_buffer → read_source >> ssl_stream.read_byte_flow() >> read_sink
  ByteFlowSource read_source;
  ByteFlowSink read_sink;

  // Write path: app_write_buf → write_source >> ssl_stream.write_byte_flow() >> write_sink
  ByteFlowSource write_source;
  ByteFlowMoveSink write_sink;

  // Wire the ByteFlow pipeline. Must be called exactly once after ssl_stream is created.
  // ciphertext_input  = &socket_fd.input_buffer()   (ciphertext from network)
  // ciphertext_output = &socket_fd.output_buffer()   (ciphertext to network)
  void wire(ChainBufferReader *ciphertext_input, ChainBufferWriter *ciphertext_output) {
    app_write_reader = app_write_buf.extract_reader();
    read_source = ByteFlowSource(ciphertext_input);
    write_source = ByteFlowSource(&app_write_reader);
    write_sink = ByteFlowMoveSink(ciphertext_output);

    read_source >> ssl_stream.read_byte_flow() >> read_sink;
    write_source >> ssl_stream.write_byte_flow() >> write_sink;
  }

  // Rewire the pipeline to a new socket fd's buffers.
  // Called when the pipeline is transferred from WebSocketType3Proxy to RawConnection.
  // The SslStream byte flow chain stays intact; we just rebind the
  // endpoints (source reader + sink writer) which hold raw pointers.
  void rewire(ChainBufferReader *new_ciphertext_input, ChainBufferWriter *new_ciphertext_output) {
    // ByteFlowSource::set_parent has CHECK(parent_ == nullptr), so we can't
    // re-chain via operator>>. Instead we replace the source/sink entirely
    // and re-chain from scratch. The ssl_stream byte flows accept re-wiring
    // because we create fresh ByteFlowSource/ByteFlowSink objects.
    //
    // The old read_source/write_sink are destroyed (move-assigned over).
    // The ssl_stream byte flows' input_ pointers still reference the old buffers,
    // but set_parent -> set_input will overwrite them.
    //
    // IMPORTANT: ByteFlowSink::set_input has CHECK(buffer_ == nullptr).
    // ByteFlowBaseCommon::set_input (via ByteFlowBase) also checks.
    // So we MUST create entirely new sink objects too.
    read_source = ByteFlowSource(new_ciphertext_input);
    read_sink = ByteFlowSink();
    write_source = ByteFlowSource(&app_write_reader);
    write_sink = ByteFlowMoveSink(new_ciphertext_output);

    read_source >> ssl_stream.read_byte_flow() >> read_sink;
    write_source >> ssl_stream.write_byte_flow() >> write_sink;
  }

  // Pump both directions of the TLS byte flow pipeline.
  void pump() {
    read_source.wakeup();
    write_source.wakeup();
  }

  // Get the decrypted output for the transport to read from.
  ChainBufferReader *plaintext_input() {
    return read_sink.get_output();
  }

  // Get the plaintext write buffer for the transport to write into.
  ChainBufferWriter *plaintext_output() {
    return &app_write_buf;
  }
};

}  // namespace td
// === TYPE3-PROXY END ===
