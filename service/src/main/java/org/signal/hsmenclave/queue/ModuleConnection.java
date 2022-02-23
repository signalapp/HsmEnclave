/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

import com.ncipher.km.nfkm.SecurityWorld;
import com.ncipher.nfast.NFException;
import com.ncipher.nfast.connect.ClientException;
import com.ncipher.nfast.connect.CommandTooBig;
import com.ncipher.nfast.connect.ConnectionClosed;
import com.ncipher.nfast.connect.StatusNotOK;
import com.ncipher.nfast.connect.utils.EasyConnection;
import com.ncipher.nfast.marshall.M_ByteBlock;
import com.ncipher.nfast.marshall.M_Cmd;
import com.ncipher.nfast.marshall.M_Cmd_Args_CreateSEEWorld;
import com.ncipher.nfast.marshall.M_Cmd_Args_SEEJob;
import com.ncipher.nfast.marshall.M_Cmd_Args_TraceSEEWorld;
import com.ncipher.nfast.marshall.M_Cmd_Reply_CreateSEEWorld;
import com.ncipher.nfast.marshall.M_Cmd_Reply_SEEJob;
import com.ncipher.nfast.marshall.M_Cmd_Reply_TraceSEEWorld;
import com.ncipher.nfast.marshall.M_Command;
import com.ncipher.nfast.marshall.M_KeyID;
import com.ncipher.nfast.marshall.M_Reply;
import com.ncipher.nfast.marshall.MarshallTypeError;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.annotation.PreDestroy;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** A connection to an nCipher HSM module. */
@Context
@Requires(env = "hsm")
class ModuleConnection implements OsConnection {
  private static final Logger logger = LoggerFactory.getLogger(ModuleConnection.class);

  private EasyConnection conn;
  private M_KeyID world;

  // Maximum time to sleep between tracing.  We keep this small, as it has the
  // added benefit of handling issues with large-sized messages,
  // where a returning value from the HSM of size >7k will block until another request
  // comes in.  Tracing is such a request.
  private static final int MAX_TRACE_SLEEP_MILLIS = 100;
  // If tracing fails, we allow for a longer maximum sleep time, to avoid spamming
  // failures.
  private static final int TRACE_FAILURE_RETRY_MILLIS = 1_000;

  private final ScheduledExecutorService traceExecutor = Executors.newSingleThreadScheduledExecutor();

  private final String userDataFilename;

  final SecurityWorld securityWorld;
  private final byte[] userDataBytes;

  private final Runnable tracer = new Runnable() {
    int millis = 1;

    @Override
    public void run() {
      try {
        while (true) {
          byte[] traceBytes = trace();
          if (traceBytes.length == 0) {
            millis = Integer.min(millis * 2, MAX_TRACE_SLEEP_MILLIS);
            break;
          }
          millis = 1;  // we're going to loop immediately, but make the next time we sleep short, too
          for (String line : new String(traceBytes, StandardCharsets.UTF_8)
              .split("\\n")) {
            if (!line.isEmpty() && !"\0".equals(line)) {
              logger.info("TRACE: {}", line);
            }
          }
        }
      } catch (Exception e) {
        logger.error("Tracing failed", e);
        millis = Integer.min(millis * 2, TRACE_FAILURE_RETRY_MILLIS);
      }
      traceExecutor.schedule(this, millis, TimeUnit.MILLISECONDS);
    }
  };

  public ModuleConnection(
    @Value("${module.userdata-filename}") String userDataFilename,
    @Value("${module.number}") int module) throws OsException {
    logger.info("Creating connection to HSM {}", module);

    this.userDataFilename = userDataFilename;

    try {
      userDataBytes = loadUserDataBytes();
      logger.info("Loaded userdata: {} bytes", userDataBytes.length);
    } catch (IOException e) {
      throw new OsException("loading userdata failed", e);
    }
    try {
      this.conn = EasyConnection.connect();
      securityWorld = new SecurityWorld(this.conn.getConnection(), null);
      M_Command cmd = new M_Command();
      cmd.cmd = M_Cmd.CreateSEEWorld;
      cmd.args = new M_Cmd_Args_CreateSEEWorld(M_Cmd_Args_CreateSEEWorld.flags_EnableDebug, conn.loadBuffer(module, userDataBytes));
      M_Reply rep = conn.transactChecked(cmd);
      world = ((M_Cmd_Reply_CreateSEEWorld) (rep.reply)).worldid;
      if (0 != ((M_Cmd_Reply_CreateSEEWorld) (rep.reply)).initstatus.value) {
        throw new OsException("nCipher CreateSEEWorld creation initstatus nonzero");
      }
    } catch (NFException e) {
      throw new OsException("nCipher CreateSEEWorld failed", e);
    }
    traceExecutor.execute(tracer);
  }

  private byte[] loadUserDataBytes() throws IOException {
    try (final InputStream is = new FileInputStream(userDataFilename)) {
      return is.readAllBytes();
    }
  }

  @PreDestroy
  public void stop() throws InterruptedException {
    logger.info("Stopping module connection");
    traceExecutor.shutdown();
  }

  @Override
  public Object send(final byte[] request) throws OsException {
    try {
      return conn.getConnection().submit(new M_Command(M_Cmd.SEEJob, 0, new M_Cmd_Args_SEEJob(world, new M_ByteBlock(request))));
    } catch (Exception e) {
      throw new OsException("submitting", e);
    }
  }

  @Override
  public byte[] receive(final Object ref) throws OsException {
    try {
      return ((M_Cmd_Reply_SEEJob)conn.getConnection().wait(ref).reply).seereply.value;
    } catch (Exception e) {
      throw new OsException("nCipher error", e);
    }
  }

  public byte[] trace()
      throws MarshallTypeError, CommandTooBig, ClientException, ConnectionClosed, StatusNotOK {
    M_Cmd_Args_TraceSEEWorld args = new M_Cmd_Args_TraceSEEWorld(world);
    M_Reply rep = conn.transactChecked(new M_Command(M_Cmd.TraceSEEWorld, 0, args));
    return ((M_Cmd_Reply_TraceSEEWorld) rep.reply).data.value;
  }
}
