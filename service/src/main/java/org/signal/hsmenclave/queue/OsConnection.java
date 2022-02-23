/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

/** Abstract connection to a backend that has an HsmEnclave instance behind it.
 *
 * This exposes a relatively nCipher-specific implementation.  Users of this
 * class must code based on the following guarantees:
 *   1) "send" is called serially
 *   2) "receive" is called serially
 *   3) "receive(x)" is called in-order with the "x" returned from "x = send()"
 */
interface OsConnection {
  Object send(byte[] request) throws OsException;
  byte[] receive(Object ref) throws OsException;
}
