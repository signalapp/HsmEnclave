/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.signal.hsmenclave.queue.message.Response;
import org.signal.hsmenclave.queue.message.Response.ResponseMessages;

class ResponseTest {

  @Test
  void parsesFromBytes() {
    byte[] b = {
        0x00, 0x00, 0x10, 0x00,  // type = responsemsgs
        0x00, 0x00, 0x00, 0x00,  // process ID
        0x00, 0x00, 0x00, 0x00,  // channel ID
        0x00, 0x00, 0x00, 0x04,  // extrabytes size
        0x00, 0x00, 0x00, 0x07,  // number
    };

    final Response response = Response.fromBytes(b);

    assertTrue(response instanceof ResponseMessages);
    Assertions.assertEquals(response.getProcessId(), 0);
    Assertions.assertEquals(response.getChannelId(), 0);
    Assertions.assertEquals(((ResponseMessages) response).getResponseMessageCount(), 7);
  }

  @Test
  void parsesFromBytesValidationFailure() {
      byte[] b = {
          0x00, 0x00, 0x10, 0x00,  // type = responsemsgs
          0x00, 0x00, 0x00, 0x00,  // process ID
          0x00, 0x00, 0x00, 0x00,  // channel ID
          0x00, 0x00, 0x00, 0x03,  // extrabytes size
          0x00, 0x00, 0x00,  // invalid, should be 4 bytes for this type
      };

      assertThrows(IllegalArgumentException.class, () -> Response.fromBytes(b));
    }
}
