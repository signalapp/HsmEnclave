/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.util;

import java.util.concurrent.atomic.AtomicLong;

public class NanoDiff {
  private AtomicLong last = new AtomicLong(System.nanoTime());
  public long nanosDelta() {
    Long now = System.nanoTime();
    Long last = this.last.getAndSet(now);
    return now - last;
  }
}
