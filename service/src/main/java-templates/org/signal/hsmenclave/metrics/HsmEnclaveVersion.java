/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.metrics;

class HsmEnclaveVersion {

  private static final String VERSION = "${project.version}";

  public static String getVersion() {
    return VERSION;
  }
}
