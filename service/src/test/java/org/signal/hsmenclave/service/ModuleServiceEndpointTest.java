/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status.Code;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import io.micronaut.context.annotation.Bean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.grpc.annotation.GrpcChannel;
import io.micronaut.grpc.server.GrpcEmbeddedServer;
import io.micronaut.grpc.server.GrpcServerChannel;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.signal.hsmenclave.ModuleProto.ChannelInit;
import org.signal.hsmenclave.ModuleProto.ChannelRequest;
import org.signal.hsmenclave.ModuleProto.ChannelResponse;
import org.signal.hsmenclave.ModuleProto.ChannelType;
import org.signal.hsmenclave.ModuleProto.CrossProcessChannelCreateRequest;
import org.signal.hsmenclave.ModuleProto.CrossProcessChannelCreateResponse;
import org.signal.hsmenclave.ModuleProto.ProcessCreateRequest;
import org.signal.hsmenclave.ModuleProto.ProcessCreateResponse;
import org.signal.hsmenclave.ModuleProto.ProcessDestroyRequest;
import org.signal.hsmenclave.ModuleServiceGrpc;
import org.signal.hsmenclave.TestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@MicronautTest
class ModuleServiceEndpointTest {
  private static final Logger logger = LoggerFactory.getLogger(ModuleServiceEndpointTest.class);

  @Factory
  static class HsmEnclaveServiceTestClientFactory {

    @Bean
    ModuleServiceGrpc.ModuleServiceStub stub(
        @GrpcChannel(GrpcServerChannel.NAME) final ManagedChannel channel) {

      return ModuleServiceGrpc.newStub(channel);
    }

    @Bean
    ModuleServiceGrpc.ModuleServiceBlockingStub blockingStub(
        @GrpcChannel(GrpcServerChannel.NAME) final ManagedChannel channel) {

      return ModuleServiceGrpc.newBlockingStub(channel);
    }
  }

  @Inject
  ModuleServiceGrpc.ModuleServiceStub stub;

  @Inject
  ModuleServiceGrpc.ModuleServiceBlockingStub blockingStub;

  @Inject
  GrpcEmbeddedServer grpcServer;

  @Inject
  ModuleServiceEndpoint endpoint;

  @BeforeEach
  void reset() throws Exception {
    endpoint.reset();
  }

  @Test
  void processCreateAndChannel() throws Exception {
    byte[] code = TestUtil.getResourceBytes(getClass(), "echo_n_times.lua");
    final ProcessCreateResponse create = blockingStub
        .processCreate(ProcessCreateRequest.newBuilder()
            .setLuaCode(ByteString.copyFrom(code))
            .build());
    assertNotEquals(0, create.getProcessId());
    int processId = create.getProcessId();

    // Set up channel
    BlockingQueue<ChannelResponse> channelResponses = new LinkedBlockingQueue<>();
    CountDownLatch chanLatch = new CountDownLatch(1);
    final Throwable[] clientError = {null};
    final StreamObserver<ChannelRequest> chanStream = stub.channel(
        new StreamObserver<ChannelResponse>() {
          @Override
          public void onNext(final ChannelResponse clientChannelResponse) {
            try {
              channelResponses.put(clientChannelResponse);
            } catch (InterruptedException e) {
              throw new AssertionError(e);
            }
          }

          @Override
          public void onError(final Throwable throwable) {
            clientError[0] = throwable;
            chanLatch.countDown();
          }

          @Override
          public void onCompleted() {
            chanLatch.countDown();
          }
        });

    chanStream.onNext(ChannelRequest.newBuilder()
        .setInit(ChannelInit.newBuilder()
            .setProcessId(processId)
            .setChannelType(ChannelType.CHANNEL_TYPE_UNENCRYPTED))
        .build());
    chanStream.onNext(ChannelRequest.newBuilder()
        .setChannelMessage(ByteString.copyFrom("abc", StandardCharsets.UTF_8))
        .build());
    chanStream.onNext(ChannelRequest.newBuilder()
        .setChannelMessage(ByteString.copyFrom("def", StandardCharsets.UTF_8))
        .build());
    assertNotEquals(0, channelResponses.take().getChannelId());
    assertEquals(
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("abc1", StandardCharsets.UTF_8)).build(),
        channelResponses.take());
    assertEquals(
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("def2", StandardCharsets.UTF_8)).build(),
        channelResponses.take());
    assertEquals(
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("def2", StandardCharsets.UTF_8)).build(),
        channelResponses.take());

    // Kill the process.
    blockingStub.processDestroy(ProcessDestroyRequest.newBuilder()
        .setProcessId(processId)
        .build());

    // Send message, because process is closed this should now error out.
    chanStream.onNext(ChannelRequest.newBuilder()
        .setChannelMessage(ByteString.copyFrom("ghi", StandardCharsets.UTF_8))
        .build());
    assertTrue(chanLatch.await(1, TimeUnit.SECONDS));
    assertNotNull(clientError[0]);
    assertTrue(channelResponses.isEmpty());
  }
  @Test
  void processClosedByLua() throws Exception {
    byte[] code = TestUtil.getResourceBytes(getClass(), "echo_and_close.lua");
    final ProcessCreateResponse create = blockingStub
        .processCreate(ProcessCreateRequest.newBuilder()
            .setLuaCode(ByteString.copyFrom(code))
            .build());
    assertNotEquals(0, create.getProcessId());
    int processId = create.getProcessId();

    sendMessagesExpectingResponses(
        ChannelInit.newBuilder()
            .setProcessId(processId)
            .setChannelType(ChannelType.CHANNEL_TYPE_UNENCRYPTED)
            .build(),
        List.of(new byte[]{0}),
        List.of("status=0".getBytes(StandardCharsets.UTF_8)),
        Code.OK);

    Code returnCode = Code.INVALID_ARGUMENT;
    sendMessagesExpectingResponses(
        ChannelInit.newBuilder()
            .setProcessId(processId)
            .setChannelType(ChannelType.CHANNEL_TYPE_UNENCRYPTED)
            .build(),
        List.of(new byte[]{(byte) returnCode.value()}),
        List.of(("status=" + returnCode.value()).getBytes(StandardCharsets.UTF_8)),
        returnCode);

    returnCode = Code.DEADLINE_EXCEEDED;
    sendMessagesExpectingResponses(
        ChannelInit.newBuilder()
            .setProcessId(processId)
            .setChannelType(ChannelType.CHANNEL_TYPE_UNENCRYPTED)
            .build(),
        List.of(new byte[]{(byte) returnCode.value()}),
        List.of(("status=" + returnCode.value()).getBytes(StandardCharsets.UTF_8)),
        returnCode);
  }

  void sendMessagesExpectingResponses(
      ChannelInit init,
      List<byte[]> requests,
      List<byte[]> responses,
      Code code) throws Exception {
    BlockingQueue<ChannelResponse> channelResponses = new LinkedBlockingQueue<>();
    CountDownLatch chanLatch = new CountDownLatch(1);
    final Throwable[] clientError = {null};
    boolean first = true;
    final StreamObserver<ChannelRequest> chanStream = stub.channel(
        new StreamObserver<ChannelResponse>() {
          @Override
          public void onNext(final ChannelResponse clientChannelResponse) {
            try {
              channelResponses.put(clientChannelResponse);
            } catch (InterruptedException e) {
              throw new AssertionError(e);
            }
          }

          @Override
          public void onError(final Throwable throwable) {
            logger.error("got error", throwable);
            clientError[0] = throwable;
            chanLatch.countDown();
          }

          @Override
          public void onCompleted() {
            chanLatch.countDown();
          }
        });

    chanStream.onNext(ChannelRequest.newBuilder()
        .setInit(init)
        .build());
    for (byte[] s : requests) {
      chanStream.onNext(ChannelRequest.newBuilder()
          .setChannelMessage(ByteString.copyFrom(s))
          .build());
    }
    for (byte[] s : responses.subList(1, responses.size())) {
      assertEquals(
          ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom(s)).build(),
          channelResponses.take());
    }
    assertTrue(chanLatch.await(1, TimeUnit.SECONDS));
    if (code == Code.OK) {
      assertNull(clientError[0]);
    } else {
      assertNotNull(clientError[0]);
      assertTrue(clientError[0] instanceof StatusRuntimeException);
      StatusRuntimeException e = (StatusRuntimeException) clientError[0];
      assertEquals(code, e.getStatus().getCode());
    }
  }

  /** Test KK with a "localhost" connection to a single process.
   *
   * This test creates a single process, then creates a loopback KK connection, using that process
   * as both the initiator and the responder.  Its lua code receives a message from an unencrypted
   * channel, passing it out the KK channel, receiving it on the other end of the KK channel, and
   * passing it out the unencrypted channel.  The message should be unchanged by the time it makes
   * it back out.
   */
  @Test
  void testKKConnection() throws Exception {
    logger.info("Running on {}", grpcServer.getPort());
    byte[] code = TestUtil.getResourceBytes(getClass(), "noise_kk.lua");
    logger.info("Using code:\n{}", new String(code, StandardCharsets.UTF_8));
    final ProcessCreateResponse create = blockingStub
        .processCreate(ProcessCreateRequest.newBuilder()
            .setLuaCode(ByteString.copyFrom(code))
            .build());
    assertNotEquals(0, create.getProcessId());
    ByteString codeHash = create.getCodeHash();

    // Set up KK channel
    logger.info("Starting KK creation");
    final CrossProcessChannelCreateResponse crossProcess = blockingStub.crossProcessChannelCreate(
        CrossProcessChannelCreateRequest.newBuilder()
            .setCodeHash(codeHash)
            .setRemoteHostAddress("localhost:" + grpcServer.getPort())  // process, talk to thyself
            .build());
    logger.info("Finished KK creation");

    // Set up unencrypted channel
    BlockingQueue<ChannelResponse> channelResponses = new LinkedBlockingQueue<>();
    CountDownLatch chanLatch = new CountDownLatch(1);
    final Throwable[] clientError = {null};
    final StreamObserver<ChannelRequest> chanStream = stub.channel(
        new StreamObserver<ChannelResponse>() {
          @Override
          public void onNext(final ChannelResponse clientChannelResponse) {
            try {
              channelResponses.put(clientChannelResponse);
            } catch (InterruptedException e) {
              throw new AssertionError(e);
            }
          }

          @Override
          public void onError(final Throwable throwable) {
            clientError[0] = throwable;
            chanLatch.countDown();
          }

          @Override
          public void onCompleted() {
            chanLatch.countDown();
          }
        });
    chanStream.onNext(ChannelRequest.newBuilder()
        .setInit(ChannelInit.newBuilder()
            .setCodeHash(codeHash)
            .setChannelType(ChannelType.CHANNEL_TYPE_UNENCRYPTED))
        .build());
    chanStream.onNext(ChannelRequest.newBuilder()
        .setChannelMessage(ByteString.copyFrom("abc", StandardCharsets.UTF_8))
        .build());
    assertNotEquals(0, channelResponses.take().getChannelId());
    assertEquals(ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("abc", StandardCharsets.UTF_8)).build(), channelResponses.take());
    chanStream.onCompleted();
    assertTrue(chanLatch.await(1, TimeUnit.SECONDS));
  }

  @Test
  void testChannelReordering() throws Exception {
    logger.info("Running on {}", grpcServer.getPort());
    byte[] code = TestUtil.getResourceBytes(getClass(), "noise_kk_multiple.lua");
    logger.info("Using code:\n{}", new String(code, StandardCharsets.UTF_8));
    final ProcessCreateResponse create = blockingStub
        .processCreate(ProcessCreateRequest.newBuilder()
            .setLuaCode(ByteString.copyFrom(code))
            .build());
    assertNotEquals(0, create.getProcessId());
    ByteString codeHash = create.getCodeHash();

    // Set up KK channel
    logger.info("Starting KK creation");
    final CrossProcessChannelCreateResponse crossProcess = blockingStub.crossProcessChannelCreate(
        CrossProcessChannelCreateRequest.newBuilder()
            .setCodeHash(codeHash)
            .setRemoteHostAddress("localhost:" + grpcServer.getPort())  // process, talk to thyself
            .build());
    logger.info("Finished KK creation");

    List<BlockingQueue<ChannelResponse>> resps = new ArrayList<>();
    List<CountDownLatch> latches = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      // Set up unencrypted channel
      BlockingQueue<ChannelResponse> channelResponses = new LinkedBlockingQueue<>();
      resps.add(channelResponses);
      CountDownLatch chanLatch = new CountDownLatch(1);
      latches.add(chanLatch);
      final Throwable[] clientError = {null};
      final StreamObserver<ChannelRequest> chanStream = stub.channel(
          new StreamObserver<ChannelResponse>() {
            @Override
            public void onNext(final ChannelResponse clientChannelResponse) {
              try {
                channelResponses.put(clientChannelResponse);
              } catch (InterruptedException e) {
                throw new AssertionError(e);
              }
            }

            @Override
            public void onError(final Throwable throwable) {
              clientError[0] = throwable;
              chanLatch.countDown();
            }

            @Override
            public void onCompleted() {
              chanLatch.countDown();
            }
          });
      chanStream.onNext(ChannelRequest.newBuilder()
          .setInit(ChannelInit.newBuilder()
              .setCodeHash(codeHash)
              .setChannelType(ChannelType.CHANNEL_TYPE_UNENCRYPTED))
          .build());
      chanStream.onNext(ChannelRequest.newBuilder()
          .setChannelMessage(ByteString.copyFrom("ping", StandardCharsets.UTF_8))
          .build());
    }
    assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
      for (BlockingQueue<ChannelResponse> channelResponses : resps) {
        assertNotEquals(0, channelResponses.take().getChannelId());
        assertEquals(
            ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("pong", StandardCharsets.UTF_8)).build(),
            channelResponses.take());
      }
    });

    for (CountDownLatch latch : latches) {
      assertTrue(latch.await(1, TimeUnit.SECONDS));
    }
  }

  @Test
  void testKKConnectionReturnsNewValues() throws Exception {
    logger.info("Running on {}", grpcServer.getPort());
    byte[] code = TestUtil.getResourceBytes(getClass(), "noise_kk.lua");
    logger.info("Using code:\n{}", new String(code, StandardCharsets.UTF_8));
    final ProcessCreateResponse create = blockingStub
        .processCreate(ProcessCreateRequest.newBuilder()
            .setLuaCode(ByteString.copyFrom(code))
            .build());
    assertNotEquals(0, create.getProcessId());
    ByteString codeHash = create.getCodeHash();

    final CrossProcessChannelCreateResponse crossProcess1 = blockingStub.crossProcessChannelCreate(
        CrossProcessChannelCreateRequest.newBuilder()
            .setCodeHash(codeHash)
            .setRemoteHostAddress("localhost:" + grpcServer.getPort())  // process, talk to thyself
            .build());
    final CrossProcessChannelCreateResponse crossProcess2 = blockingStub.crossProcessChannelCreate(
        CrossProcessChannelCreateRequest.newBuilder()
            .setCodeHash(codeHash)
            .setRemoteHostAddress("localhost:" + grpcServer.getPort())  // process, talk to thyself
            .build());
    assertEquals(crossProcess1.getLocalProcessId(), crossProcess2.getLocalProcessId());
    assertNotEquals(crossProcess1.getLocalChannelId(), crossProcess2.getLocalChannelId());
  }

  @Test
  void testSendThenCloseExpectingResponses() throws Exception {
    logger.info("Running on {}", grpcServer.getPort());
    byte[] code = TestUtil.getResourceBytes(getClass(), "echo_n_times.lua");
    logger.info("Using code:\n{}", new String(code, StandardCharsets.UTF_8));
    final ProcessCreateResponse create = blockingStub
        .processCreate(ProcessCreateRequest.newBuilder()
            .setLuaCode(ByteString.copyFrom(code))
            .build());

    // Set up unencrypted channel
    BlockingQueue<ChannelResponse> channelResponses = new LinkedBlockingQueue<>();
    CountDownLatch chanLatch = new CountDownLatch(1);
    CountDownLatch waitToProcessResponses = new CountDownLatch(1);
    final Throwable[] clientError = {null};
    final StreamObserver<ChannelRequest> chanStream = stub.channel(
        new StreamObserver<ChannelResponse>() {
          @Override
          public void onNext(final ChannelResponse clientChannelResponse) {
            try {
              // We block before handling responses.  This allows us to call "onComplete" on the
              // client side before any requests are processed on the server side.  The test here
              // makes sure that when a client onComplete is called, it's handled in the order it's
              // received, not immediately, which possibly preempts the execution of other prequeued
              // requests.
              waitToProcessResponses.await();
              channelResponses.put(clientChannelResponse);
            } catch (InterruptedException e) {
              throw new AssertionError(e);
            }
          }

          @Override
          public void onError(final Throwable throwable) {
            clientError[0] = throwable;
            chanLatch.countDown();
          }

          @Override
          public void onCompleted() {
            chanLatch.countDown();
          }
        });
    chanStream.onNext(ChannelRequest.newBuilder()
        .setInit(ChannelInit.newBuilder()
            .setCodeHash(create.getCodeHash())
            .setChannelType(ChannelType.CHANNEL_TYPE_UNENCRYPTED))
        .build());
    chanStream.onNext(ChannelRequest.newBuilder()
        .setChannelMessage(ByteString.copyFrom("a", StandardCharsets.UTF_8))
        .build());
    chanStream.onNext(ChannelRequest.newBuilder()
        .setChannelMessage(ByteString.copyFrom("b", StandardCharsets.UTF_8))
        .build());
    chanStream.onNext(ChannelRequest.newBuilder()
        .setChannelMessage(ByteString.copyFrom("c", StandardCharsets.UTF_8))
        .build());
    chanStream.onCompleted();
    waitToProcessResponses.countDown();
    assertTrue(chanLatch.await(1, TimeUnit.SECONDS));
    assertEquals(7, channelResponses.size());
    assertNotEquals(0, channelResponses.take().getChannelId());
    assertEquals(List.of(
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("a1", StandardCharsets.UTF_8)).build(),
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("b2", StandardCharsets.UTF_8)).build(),
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("b2", StandardCharsets.UTF_8)).build(),
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("c3", StandardCharsets.UTF_8)).build(),
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("c3", StandardCharsets.UTF_8)).build(),
        ChannelResponse.newBuilder().setChannelMessage(ByteString.copyFrom("c3", StandardCharsets.UTF_8)).build()),
        channelResponses.stream().toList());
  }
}
