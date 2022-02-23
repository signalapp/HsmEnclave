/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue.message;

import java.nio.ByteBuffer;

class MessageHeader {

  private final int type;
  private final int processId;
  private final int channelId;
  private final int extraBytesLength;

  static final int HEADER_LENGTH = 16;

  MessageHeader(final int type, final int processId, final int channelId, final int extraBytesLength) {
    this.type = type;
    this.processId = processId;
    this.channelId = channelId;
    this.extraBytesLength = extraBytesLength;
  }

  public int getType() {
    return type;
  }

  public int getProcessId() {
    return processId;
  }

  public int getChannelId() {
    return channelId;
  }

  public int getExtraBytesLength() {
    return extraBytesLength;
  }

  byte[] toByteArray() {
    final ByteBuffer buffer = ByteBuffer.allocate(HEADER_LENGTH);

    buffer.putInt(type);
    buffer.putInt(processId);
    buffer.putInt(channelId);
    buffer.putInt(extraBytesLength);

    return buffer.array();
  }

  /**
   * Extracts a message header from the start of the given buffer. The buffer's read position is not changed by this
   * method.
   *
   * @param buffer the buffer from which to extract a message header
   * @return the message header at the start of the given buffer
   *
   * @throws IllegalArgumentException if the given buffer has fewer than {@value HEADER_LENGTH} bytes remaining
   */
  static MessageHeader fromBytes(final ByteBuffer buffer) {
    if (buffer == null || buffer.remaining() < HEADER_LENGTH) {
      throw new IllegalArgumentException("Header must be at least " + HEADER_LENGTH + " bytes");
    }

    return new MessageHeader(buffer.getInt(0), buffer.getInt(4), buffer.getInt(8), buffer.getInt(12));
  }

  @Override
  public String toString() {
    return String.format("type=%04x pid=%d cid=%d ebsz=%d", type, processId, channelId, extraBytesLength);
  }
}
