/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A simple, embedded "HSM OS" server designed for use in integration tests.
 */
public class EmbeddedHsmServer {
  private static final Logger logger = LoggerFactory.getLogger("HSM");

  private final int port;
  private Process process;

  private static final int OS_SELECT_PORT = 0;

  private static final Pattern STARTUP_PATTERN = Pattern.compile("^Listening on ([^:]+):([0-9]+)\\s*$");

  /**
   * Constructs, but does not start, a new embedded server that will listen on an unoccupied, OS-assigned port.
   */
  public EmbeddedHsmServer() {
    this(OS_SELECT_PORT);
  }

  /**
   * Constructs, but does not start, a new embedded server that will listen on the given port.
   */
  public EmbeddedHsmServer(final int port) {
    this.port = port;
  }

  /**
   * Starts the embedded server. When this method returns, the server will be ready to accept traffic at the returned
   * socket address.
   *
   * @return the socket address at which the server can be reached
   * @throws IOException if the embedded server could not be started for any reason
   */
  public InetSocketAddress start() throws IOException {
    final File executable = extractExecutable();

    process = new ProcessBuilder(executable.getAbsolutePath(), "--port", String.valueOf(this.port))
        .redirectInput(Redirect.INHERIT)
        .start();

    new Thread(() -> dumpLogs(process.getErrorStream())).start();

    try (final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
      String line = reader.readLine();
      final Matcher startupLineMatcher = STARTUP_PATTERN.matcher(line);

      if (startupLineMatcher.matches()) {
        final String host = startupLineMatcher.group(1);
        final int port = Integer.parseInt(startupLineMatcher.group(2));

        return new InetSocketAddress(host, port);
      }
    }

    throw new IOException("Failed to start embedded server");
  }

  private void dumpLogs(InputStream stream) {
    try (final BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
      while (true) {
        String line = reader.readLine();
        if (line == null) return;
        logger.trace("{}", line);
      }
    } catch (IOException e) {
      logger.warn("Dumping logs failed/finished: {}", e.getMessage());
    }
  }

  /**
   * Stops the embedded server.
   *
   * @throws InterruptedException if the calling thread is interrupted while waiting for the server process to exit
   */
  public void stop() throws InterruptedException {
    process.destroy();
    process.waitFor();
  }

  private File extractExecutable() throws IOException {
    final File extractedFile = File.createTempFile("hsm_enclave_native", "");
    extractedFile.deleteOnExit();

    try (final InputStream executableInputStream = getClass().getResourceAsStream("/hsm_enclave_native")) {
      if (executableInputStream == null) {
        throw new IOException("hsm_enclave_native binary resource not found");
      }

      Files.copy(executableInputStream, extractedFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
      Files.setPosixFilePermissions(extractedFile.toPath(), EnumSet.of(
          PosixFilePermission.OWNER_READ,
          PosixFilePermission.OWNER_WRITE,
          PosixFilePermission.OWNER_EXECUTE,
          PosixFilePermission.GROUP_READ,
          PosixFilePermission.GROUP_EXECUTE,
          PosixFilePermission.OTHERS_READ,
          PosixFilePermission.OTHERS_EXECUTE
      ));
    }

    return extractedFile;
  }
}
