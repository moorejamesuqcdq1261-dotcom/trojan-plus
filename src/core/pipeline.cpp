/*
 * This file is part of the trojan plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Plust Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pipeline.h"

#include "core/service.h"
#include "core/utils.h"
#include "proto/pipelinerequest.h"
#include "session/clientsession.h"

using namespace std;
using namespace boost::asio::ip;

uint32_t Pipeline::s_pipeline_id_counter = 0;

Pipeline::Pipeline(Service* _service, const Config& config, boost::asio::ssl::context& ssl_context)
    : service(_service),
      destroyed(false),
      out_socket(_service->get_io_context(), ssl_context),
      connected(false),
      resolver(_service->get_io_context()),
      config(config) {
    _guard;

    pipeline_id = s_pipeline_id_counter++;

    sending_data_cache.set_is_connected_func([this]() { return is_connected() && !destroyed; });
    sending_data_cache.set_async_writer([this](const boost::asio::streambuf& data, SentHandler&& handler) {
        auto self = shared_from_this();
        boost::asio::async_write(
          out_socket, data.data(), [this, self, handler](const boost::system::error_code error, size_t) {
              _guard;
              if (error) {
                  output_debug_info_ec(error);
                  destroy();
              }

              handler(error);
              _unguard;
          });
    });

    _unguard;
}

Pipeline::~Pipeline() { _log_with_date_time("~Pipeline called!"); }

void Pipeline::start() {
    _guard;

    auto self = shared_from_this();
    connect_remote_server_ssl(this, config.get_remote_addr(), to_string(config.get_remote_port()), resolver, out_socket,
      tcp::endpoint(), [this, self]() {
          _guard;
          connected           = true;
          out_socket_endpoint = out_socket.next_layer().remote_endpoint();

          string data(config.get_password().cbegin()->first);
          data += "\r\n";
          sending_data_cache.insert_data(move(data));

          if (Log::level <= Log::INFO) {
              _log_with_date_time(
                "pipeline " + to_string(get_pipeline_id()) + " is going to connect remote server and send password...",
                Log::INFO);
          }
          out_async_recv();
          _unguard;
      });

    _unguard;
}

void Pipeline::session_async_send_cmd(PipelineRequest::Command cmd, Session& session, const std::string_view& send_data,
  SentHandler&& sent_handler, size_t ack_count /* = 0*/) {
    _guard;
    if (destroyed) {
        sent_handler(boost::asio::error::broken_pipe);
        return;
    }

    if (Log::level <= Log::ALL) {
        _log_with_date_time_ALL("pipeline " + to_string(get_pipeline_id()) +
                                " session_id: " + to_string(session.get_session_id()) +
                                " --> send to server cmd: " + PipelineRequest::get_cmd_string(cmd) +
                                (cmd == PipelineRequest::ACK ? (" ack count: " + to_string(ack_count))
                                                             : (" data length:" + to_string(send_data.length()))) +
                                " checksum: " + to_string(get_checksum(send_data)));
    }

    sending_data_cache.push_data(
      [&](boost::asio::streambuf& buf) {
          PipelineRequest::generate(buf, cmd, session.get_session_id(), send_data, ack_count);
      },
      move(sent_handler));

    _unguard;
}

void Pipeline::session_async_send_icmp(const std::string_view& send_data, SentHandler&& sent_handler) {
    _guard;
    if (destroyed) {
        sent_handler(boost::asio::error::broken_pipe);
        return;
    }

    if (Log::level <= Log::ALL) {
        _log_with_date_time_ALL("pipeline " + to_string(get_pipeline_id()) +
                                " --> send to server cmd: ICMP data length:" + to_string(send_data.length()));
    }

    sending_data_cache.push_data(
      [&](boost::asio::streambuf& buf) { PipelineRequest::generate(buf, PipelineRequest::ICMP, 0, send_data); },
      move(sent_handler));

    _unguard;
}

void Pipeline::session_start(Session& session, SentHandler&& started_handler) {
    _guard;
    auto shared_session = session.shared_from_this();
    sessions.emplace(session.get_session_id(), shared_session);
    session.get_pipeline_component().set_pipeline_owner(shared_from_this());
    session_async_send_cmd(PipelineRequest::CONNECT, session, "", move(started_handler));
    _unguard;
}

void Pipeline::session_destroyed(Session& session) {
    _guard;
    if (!destroyed) {
        auto it = sessions.find(session.get_session_id());
        if (it != sessions.end()) {
            sessions.erase(it);
        }
        session.get_pipeline_component().reset_pipeline_owner();
        if (Log::level <= Log::ALL) {
            _log_with_date_time_ALL("pipeline " + to_string(get_pipeline_id()) +
                                    " send command to close session_id: " + to_string(session.get_session_id()));
        }
        session_async_send_cmd(PipelineRequest::CLOSE, session, "", [](boost::system::error_code) {});
    }
    _unguard;
}

bool Pipeline::is_in_pipeline(Session& session) {
    _guard;
    bool result = sessions.find(session.get_session_id()) != sessions.end();
    return result;
    _unguard;
}

void Pipeline::out_async_recv() {
    _guard;
    out_read_buf.begin_read(__FILE__, __LINE__);
    auto self = shared_from_this();
    out_socket.async_read_some(
      out_read_buf.prepare(RECV_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
          _guard;
          out_read_buf.end_read();
          if (error) {
              output_debug_info_ec(error);
              destroy();
          } else {
              out_read_buf.commit(length);
              while (out_read_buf.size() != 0) {
                  PipelineRequest req;
                  int ret = req.parse(out_read_buf);
                  if (ret == -1) {
                      break;
                  }

                  if (ret == -2) {
                      output_debug_info();
                      destroy();
                      return;
                  }

                  if (Log::level <= Log::ALL) {
                      _log_with_date_time_ALL(
                        "pipeline " + to_string(get_pipeline_id()) + " session_id: " + to_string(req.session_id) +
                        " <-- recv from server cmd: " + req.get_cmd_string() +
                        (req.command == PipelineRequest::ACK ? (" ack count: " + to_string(req.ack_count))
                                                             : (" data length: " + to_string(req.packet_data.length()))) +
                        " checksum: " + to_string(get_checksum(req.packet_data)));
                  }

                  if (req.command == PipelineRequest::ICMP) {
                      if (icmp_processor) {
                          icmp_processor->client_out_send(string(req.packet_data));
                      }
                  } else {

                      auto it = sessions.find(req.session_id);
                      if (it != sessions.end()) {
                          auto& session = it->second;
                          if (req.command == PipelineRequest::CLOSE) {
                              if (session->get_pipeline_component().canbe_closed_by_pipeline()) {
                                  output_debug_info();
                                  session->destroy(true);
                                  sessions.erase(it);
                              } else {
                                  session->get_pipeline_component().set_write_close_future(true);
                              }
                          } else if (req.command == PipelineRequest::ACK) {
                              session->recv_ack_cmd(req.ack_count);
                          } else {
                              session->get_pipeline_component().pipeline_in_recv(req.packet_data);
                          }
                      } else {

                          _log_with_date_time("pipeline " + to_string(get_pipeline_id()) +
                                                " cannot find session_id:" + to_string(req.session_id) +
                                                " current sessions:" + to_string(sessions.size()),
                            Log::ERROR);
                      }
                  }

                  out_read_buf.consume(req.consume_length);
              }

              out_async_recv();
          }
          _unguard;
      });

    _unguard;
}

void Pipeline::destroy() {
    _guard;

    if (destroyed) {
        return;
    }
    destroyed = true;

    _log_with_date_time("pipeline " + to_string(get_pipeline_id()) + " destroyed. close all " +
                          to_string(sessions.size()) + " sessions in this pipeline.",
      Log::INFO);

    sending_data_cache.destroy();

    // close all sessions
    for (auto& kv : sessions) {
        kv.second->get_pipeline_component().reset_pipeline_owner();
        kv.second->destroy(true);
    }
    sessions.clear();

    resolver.cancel();
    shutdown_ssl_socket(this, out_socket);

    _unguard;
}