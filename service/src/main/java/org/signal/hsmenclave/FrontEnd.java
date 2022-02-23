/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave;

import io.micronaut.runtime.Micronaut;

public class FrontEnd {

    public static void main(String[] args) {
        Micronaut.run(FrontEnd.class, args);
    }
}
