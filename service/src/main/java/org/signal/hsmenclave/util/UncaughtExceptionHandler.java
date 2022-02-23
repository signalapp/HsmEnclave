/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.util;

import io.micronaut.context.annotation.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.annotation.PostConstruct;

@Context
class UncaughtExceptionHandler {

  private static final Logger logger = LoggerFactory.getLogger(UncaughtExceptionHandler.class);

  @PostConstruct
  void register() {
    @Nullable final Thread.UncaughtExceptionHandler current = Thread.getDefaultUncaughtExceptionHandler();

    if (current != null) {
      logger.warn("Uncaught exception handler already exists: {}", current);
      return;
    }

    Thread.setDefaultUncaughtExceptionHandler((t, e) -> logger.error("Uncaught exception on thread {}", t, e));
  }

}
