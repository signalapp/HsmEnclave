/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue.message;

import io.micronaut.core.annotation.Nullable;
import java.nio.ByteBuffer;

/** A request that we may send to HsmEnclave. */
public class Request {

  private final MessageHeader header;

  @Nullable
  private final byte[] extraBytes;

  private static final int REQUEST_TYPE_POLL = 0x00;
  private static final int REQUEST_TYPE_CHANNEL_MESSAGE = 0x01;
  private static final int REQUEST_TYPE_CLOSE_CHANNEL = 0x02;
  private static final int REQUEST_TYPE_CREATE_PROCESS = 0x10;
  private static final int REQUEST_TYPE_DESTROY_PROCESS = 0x11;
  private static final int REQUEST_TYPE_LIST_PROCESS = 0x12;
  private static final int REQUEST_TYPE_CREATE_RAW_CHANNEL = 0x20;
  private static final int REQUEST_TYPE_CREATE_CLIENT_NK_CHANNEL = 0x21;
  private static final int REQUEST_TYPE_CREATE_CLIENT_KK_CHANNEL_INIT = 0x22;
  private static final int REQUEST_TYPE_CREATE_CLIENT_KK_CHANNEL_RESP = 0x23;
  private static final int REQUEST_TYPE_HSM_RESET_REQUEST = 0x30;

  private static final Request POLL_REQUEST = new Request(REQUEST_TYPE_POLL, 0, 0, null);
  public static final Request RESET_REQUEST = new Request(REQUEST_TYPE_HSM_RESET_REQUEST, 0, 0, null);
  public static final Request LIST_REQUEST = new Request(REQUEST_TYPE_LIST_PROCESS, 0, 0, null);

  private Request(final int type, final int processId, final int channelId, @Nullable final byte[] extraBytes) {
    this.header = new MessageHeader(type, processId, channelId, extraBytes != null ? extraBytes.length : 0);
    this.extraBytes = extraBytes;
  }

  public static Request buildPollRequest() {
    return POLL_REQUEST;
  }

  public static Request buildChannelMessageRequest(final int processId, final int channelId, final byte[] payload) {
    return new Request(REQUEST_TYPE_CHANNEL_MESSAGE, processId, channelId, payload);
  }

  public static Request buildChannelMessageRequest(final int processId, final int channelId, ByteBuffer buf) {
    byte[] payload = new byte[buf.remaining()];
    buf.slice().get(payload);
    return new Request(REQUEST_TYPE_CHANNEL_MESSAGE, processId, channelId, payload);
  }

  public static Request buildCloseChannelRequest(final int processId, final int channelId) {
    return new Request(REQUEST_TYPE_CLOSE_CHANNEL, processId, channelId, null);
  }

  public static Request buildCreateProcessRequest(final byte[] src) {
    return new Request(REQUEST_TYPE_CREATE_PROCESS, 0, 0, src);
  }

  public static Request buildDestroyProcessRequest(final int processId) {
    return new Request(REQUEST_TYPE_DESTROY_PROCESS, processId, 0, null);
  }

  public static Request buildCreateRawChannelRequest(final int processId) {
    return new Request(REQUEST_TYPE_CREATE_RAW_CHANNEL, processId, 0, null);
  }

  public static Request buildCreateClientNkChannelRequest(final int processId) {
    return new Request(REQUEST_TYPE_CREATE_CLIENT_NK_CHANNEL, processId, 0, null);
  }

  public static Request buildCreateClientKkChannelInitRequest(final int processId) {
    return new Request(REQUEST_TYPE_CREATE_CLIENT_KK_CHANNEL_INIT, processId, 0, null);
  }

  public static Request buildCreateClientKkChannelRespRequest(final int processId) {
    return new Request(REQUEST_TYPE_CREATE_CLIENT_KK_CHANNEL_RESP, processId, 0, null);
  }

  public byte[] toByteArray() {
    final ByteBuffer buffer = ByteBuffer.allocate(MessageHeader.HEADER_LENGTH + (extraBytes != null ? extraBytes.length : 0));

    buffer.put(header.toByteArray());

    if (extraBytes != null) {
      buffer.put(extraBytes);
    }

    return buffer.array();
  }

  @Override
  public String toString() {
    return header.toString();
  }
}
