/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.micronaut.runtime.EmbeddedApplication;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;


@MicronautTest
class FrontEndTest {

  @Inject
  EmbeddedApplication<?> frontEnd;

  @Test
  void testItWorks() {
    assertTrue(frontEnd.isRunning());
  }

}
