/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

public class TestUtil {
  public static byte[] getResourceBytes(Class cls, String filename) {
    try (final InputStream inputStream = cls.getResourceAsStream(filename)) {
      if (inputStream == null) {
        throw new IOException("Test script not found");
      }

      return inputStream.readAllBytes();
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
