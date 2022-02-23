/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.Test;

class EmbeddedHsmServerTest {

  @Test
  void startStop() throws InterruptedException {
    final EmbeddedHsmServer embeddedHsmServer = new EmbeddedHsmServer();

    assertDoesNotThrow(embeddedHsmServer::start);
    assertDoesNotThrow(embeddedHsmServer::stop);
  }
}
