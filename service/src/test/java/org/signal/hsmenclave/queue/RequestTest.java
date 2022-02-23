/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.signal.hsmenclave.queue.message.Request;

class RequestTest {

  @Test
  void parsesFromBytes() {
    byte[] b = {
        0x00, 0x00, 0x00, 0x00,  // type = noop
        0x00, 0x00, 0x00, 0x00,  // process ID
        0x00, 0x00, 0x00, 0x00,  // channel ID
        0x00, 0x00, 0x00, 0x00,  // extrabytes size
    };

    Assertions.assertArrayEquals(b, Request.buildPollRequest().toByteArray());
  }
}
