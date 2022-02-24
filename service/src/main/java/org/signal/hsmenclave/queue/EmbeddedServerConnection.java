/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import org.signal.hsmenclave.util.EmbeddedHsmServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

@Context
@Requires(notEnv = "hsm")
class EmbeddedServerConnection implements OsConnection {

  private final EmbeddedHsmServer embeddedHsmServer;
  private final AtomicLong ordering = new AtomicLong();
  private Long last = Long.valueOf(0);

  @Nullable
  private Socket socket;

  private static final Logger log = LoggerFactory.getLogger(EmbeddedServerConnection.class);

  public EmbeddedServerConnection() {
    this.embeddedHsmServer = new EmbeddedHsmServer();
  }

  @PostConstruct
  public synchronized void start() throws IOException {
    final InetSocketAddress embeddedServerAddress = embeddedHsmServer.start();
    socket = new Socket(embeddedServerAddress.getAddress(), embeddedServerAddress.getPort());

    log.info("Started new embedded server on port {}", embeddedServerAddress.getPort());
  }

  @PreDestroy
  public synchronized void stop() throws InterruptedException {
    socket = null;
    embeddedHsmServer.stop();
  }

  @Override
  public Object send(final byte[] requestBytes) throws OsException {
    if (socket == null) {
      throw new OsException("Socket not available");
    }

    final ByteBuffer outgoingSizeBuf = ByteBuffer.allocate(4);
    outgoingSizeBuf.putInt(requestBytes.length);
    try {
      socket.getOutputStream().write(outgoingSizeBuf.array());
      socket.getOutputStream().write(requestBytes);
    } catch (IOException e) {
      throw new OsException("writing outgoing", e);
    }
    return Long.valueOf(ordering.incrementAndGet());
  }

  @Override
  public byte[] receive(final Object ref) throws OsException {
    // This check is not actually necessary for the running of this class,
    // but it does act as a test assertion for any tests that use it to
    // verify the guarantees that receives are called in the same order as
    // sends.
    assert ((Long) ref) == (last + 1);
    last = (Long) ref;

    try {
      final byte[] size = socket.getInputStream().readNBytes(4);
      final int len = ByteBuffer.wrap(size).getInt();

      log.trace("reading {}-byte response", len);

      return socket.getInputStream().readNBytes(len);
    } catch (IOException e) {
      throw new OsException("reading incoming", e);
    }
  }
}
