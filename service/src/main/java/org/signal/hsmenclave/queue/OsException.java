/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

/** Simple exception for this codebase. */
public class OsException extends Exception {
  public OsException(String msg) {
    super(msg);
  }
  public OsException(String msg, Throwable t) {
    super(msg, t);
  }
}
