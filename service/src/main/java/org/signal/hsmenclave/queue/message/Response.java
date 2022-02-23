/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue.message;

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.codec.binary.Hex;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public abstract class Response {

  private final MessageHeader header;
  private final ByteBuffer payload;

  public static class ResponseMessages extends Response {

    public ResponseMessages(final int processId, final int channelId, final int responseMessageCount) {
      super(new MessageHeader(Type.ResponseMessages.value, processId, channelId, 4), ByteBuffer.allocate(4).putInt(responseMessageCount).flip());
    }

    public int getResponseMessageCount() {
      return getPayload().getInt();
    }

    @Override
    public String toString() {
      return String.format("ResponseMsgs=%d", getResponseMessageCount());
    }

    @Override
    public boolean equals(Object o) {
      if (o == null) return false;
      if (o == this) return true;
      if (!(o instanceof ResponseMessages)) return false;
      ResponseMessages other = (ResponseMessages) o;
      return other.getChannelId() == getChannelId() && other.getProcessId() == getProcessId() && other.getResponseMessageCount() == getResponseMessageCount();
    }
  }

  public static class ChannelMessage extends Response {

    public ChannelMessage(final int processId, final int channelId, final ByteBuffer payload) {
      super(new MessageHeader(Type.ChannelMessage.value, processId, channelId, payload.remaining()), payload);
    }

    @Override
    public String toString() {
      return String.format("ChannelMessage(%d,%d)=%d bytes", getProcessId(), getChannelId(), getPayload().remaining());
    }

    @Override
    public boolean equals(Object o) {
      if (o == null) return false;
      if (o == this) return true;
      if (!(o instanceof ChannelMessage)) return false;
      ChannelMessage other = (ChannelMessage) o;
      return other.getChannelId() == getChannelId() && other.getProcessId() == getProcessId() && other.getPayload().equals(getPayload());
    }
  }

  public static class NewID extends Response {
    public NewID(final int processId, final int channelId) {
      super(new MessageHeader(Type.ChannelNewId.value, processId, channelId, 0), ByteBuffer.allocate(0));
    }

    @Override
    public String toString() {
      return String.format("ChannelNewId(%d)=%d", getProcessId(), getChannelId());
    }

    @Override
    public boolean equals(Object o) {
      if (o == null) return false;
      if (o == this) return true;
      if (!(o instanceof NewID)) return false;
      NewID other = (NewID) o;
      return other.getChannelId() == getChannelId() && other.getProcessId() == getProcessId();
    }
  }

  public static class ProcessHash extends Response {

    public ProcessHash(int processId, int channelId, ByteBuffer payload) {
      super(new MessageHeader(Type.ResetHsm.value, processId, channelId, payload.remaining()), payload);
    }

    @Override
    public String toString() {
      return String.format("ProcessHash,pubkey=%s", Hex.encodeHexString(getPayload()));
    }

    @Override
    public boolean equals(Object o) {
      if (o == null) return false;
      if (o == this) return true;
      if (!(o instanceof ProcessHash)) return false;
      ProcessHash other = (ProcessHash) o;
      return other.getChannelId() == getChannelId() && other.getProcessId() == getProcessId() && other.getPayload().equals(getPayload());
    }
  }

  public static class ResetHsm extends Response {

    public ResetHsm(int processId, int channelId, ByteBuffer payload) {
      super(new MessageHeader(Type.ResetHsm.value, processId, channelId, payload.remaining()), payload);
    }

    @Override
    public String toString() {
      return String.format("ResetHsm,pubkey=%s", Hex.encodeHexString(getPayload()));
    }

    @Override
    public boolean equals(Object o) {
      if (o == null) return false;
      if (o == this) return true;
      if (!(o instanceof ResetHsm)) return false;
      ResetHsm other = (ResetHsm) o;
      return other.getChannelId() == getChannelId() && other.getProcessId() == getProcessId() && other.getPayload().equals(getPayload());
    }
  }

  public static class Error extends Response {

    public Error(final int processId, final int channelId, final ByteBuffer payload) {
      super(new MessageHeader(Type.Error.value, processId, channelId, payload.remaining()), payload);
    }

    @Override
    public String toString() {
      return String.format("Error=%s", StandardCharsets.UTF_8.decode(getPayload()));
    }

    @Override
    public boolean equals(Object o) {
      if (o == null) return false;
      if (o == this) return true;
      if (!(o instanceof Error)) return false;
      Error other = (Error) o;
      return other.getChannelId() == getChannelId() && other.getProcessId() == getProcessId() && other.getPayload().equals(getPayload());
    }
  }

  private enum Type {
    ResponseMessages(0x1000),
    ChannelMessage(0x1001),
    ChannelNewId(0x1002),
    ChannelClose(0x1003),
    ProcessHash(0x1004),
    ResetHsm(0x1030),
    Error(0x100F);

    final int value;

    Type(int i) {
      value = i;
    }

    private final static Map<Integer, Type> TYPES_BY_VALUE = new HashMap<>();

    static {
      for (Type type : Type.values()) {
        TYPES_BY_VALUE.put(type.value, type);
      }
    }

    static Type valueOf(final int i) {
      if (TYPES_BY_VALUE.containsKey(i)) {
        return TYPES_BY_VALUE.get(i);
      } else {
        throw new IllegalArgumentException("Unrecognized response type: " + i);
      }
    }
  }

  private Response(MessageHeader header, ByteBuffer payload) {
    this.header = header;
    this.payload = payload;
  }

  public int getProcessId() {
    return header.getProcessId();
  }

  public int getChannelId() {
    return header.getChannelId();
  }

  public ByteBuffer getPayload() {
    return payload.slice();
  }

  @VisibleForTesting
  public byte[] toByteArray() {
    byte[] headerBytes = header.toByteArray();
    ByteBuffer payload = getPayload();
    ByteBuffer bb = ByteBuffer.allocate(headerBytes.length + payload.remaining());
    bb.put(headerBytes);
    bb.put(payload);
    return bb.flip().array();
  }

  public static Response fromBytes(final byte[] bytes) {
    final ByteBuffer buffer = ByteBuffer.wrap(bytes);
    final MessageHeader header = MessageHeader.fromBytes(buffer);
    final Type responseType = Type.valueOf(header.getType());

    final ByteBuffer extraBytes = buffer.position(MessageHeader.HEADER_LENGTH).slice();

    if (header.getProcessId() < 0) {
      throw new IllegalArgumentException("Illegal process ID: " + header.getProcessId());
    }

    if (header.getChannelId() < 0) {
      throw new IllegalArgumentException("Illegal channel ID: " + header.getChannelId());
    }

    if (header.getExtraBytesLength() != extraBytes.remaining()) {
      throw new IllegalArgumentException(String.format("Extra bytes header field (%d) and payload length (%d) disagree",
          header.getExtraBytesLength(), extraBytes.remaining()));
    }

    switch (responseType) {
      case ResponseMessages:
        if (header.getExtraBytesLength() != Integer.BYTES) {
          throw new IllegalArgumentException("Message header must indicate extra bytes length of exactly " + Integer.BYTES);
        }
        if (extraBytes.remaining() != Integer.BYTES) {
          throw new IllegalArgumentException("Extra bytes must have length of exactly " + Integer.BYTES);
        }
        return new ResponseMessages(header.getProcessId(), header.getChannelId(), extraBytes.getInt());
      case ChannelClose:
        if (header.getExtraBytesLength() != Integer.BYTES) {
          throw new IllegalArgumentException("Message header must indicate extra bytes length of exactly " + Integer.BYTES);
        }
        if (extraBytes.remaining() != Integer.BYTES) {
          throw new IllegalArgumentException("Extra bytes must have length of exactly " + Integer.BYTES);
        }
        return new ChannelClose(header.getProcessId(), header.getChannelId(), extraBytes.getInt());
      case ChannelMessage:
        return new ChannelMessage(header.getProcessId(), header.getChannelId(), extraBytes);
      case ChannelNewId:
        return new NewID(header.getProcessId(), header.getChannelId());
      case ProcessHash:
        return new ProcessHash(header.getProcessId(), header.getChannelId(), extraBytes);
      case ResetHsm:
        return new ResetHsm(header.getProcessId(), header.getChannelId(), extraBytes);
      case Error:
        return new Error(header.getProcessId(), header.getChannelId(), extraBytes);
      default:
        throw new UnsupportedOperationException("Unexpected response type: " + responseType);
    }
  }

  public static class ChannelClose extends Response {

    public ChannelClose(final int processId, final int channelId, final int status) {
      super(new MessageHeader(Type.ChannelClose.value, processId, channelId, 4), ByteBuffer.allocate(4).putInt(status).flip());
    }

    public int statusCode() {
      return getPayload().getInt();
    }

    @Override
    public String toString() {
      return String.format("ChannelClose=%d", statusCode());
    }

    @Override
    public boolean equals(Object o) {
      if (o == null) return false;
      if (o == this) return true;
      if (!(o instanceof ChannelClose)) return false;
      ChannelClose other = (ChannelClose) o;
      return other.getChannelId() == getChannelId() && other.getProcessId() == getProcessId() && other.statusCode() == statusCode();
    }
  }
}
