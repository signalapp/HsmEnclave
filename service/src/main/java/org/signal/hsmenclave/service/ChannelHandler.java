/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.service;

import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.Status.Code;
import io.grpc.StatusException;
import io.grpc.stub.StreamObserver;
import org.signal.hsmenclave.ModuleProto;
import org.signal.hsmenclave.ModuleProto.ChannelInit;
import org.signal.hsmenclave.ModuleProto.ChannelRequest;
import org.signal.hsmenclave.ModuleProto.ChannelRequest.KindCase;
import org.signal.hsmenclave.ModuleProto.ChannelResponse;
import org.signal.hsmenclave.queue.message.Request;
import org.signal.hsmenclave.queue.message.Response.NewID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.Map;
import java.util.concurrent.CompletionException;

class ChannelHandler implements StreamObserver<ChannelRequest> {

  private static final Logger logger = LoggerFactory.getLogger(ChannelHandler.class);
  private final ModuleServiceEndpoint endpoint;
  private final StreamObserver<ModuleProto.ChannelResponse> responseObserver;
  private Integer processId = null;
  private Integer channelId = null;
  private boolean completed = false;
  boolean closedByProcess = false;
  // We complete our channelId future only once our handshake has completed, to the point
  // where the Lua code now knows about the handshake.  This counter tracks the number
  // of messages that must be processed by HsmEnclave to initialize a channel.
  //
  // This counts the number of messages we send _into_ the HSM associated with a channel
  // that initialize that channel, and it's checked when we get a _response_ to those
  // messages.  By the time we get the response, we know that the Lua process is aware
  // of the channel ID, not just the HsmEnclave code.
  //
  // With this approach, a caller can wait for getChannelId() to be completed, and know
  // upon that completion that the Lua process associated with the channel has been
  // made aware of its existence via HandleChannelCreate.
  //
  // Without this, we might send a message that references the channel (for example,
  // sending an unencrypted message that says "please send 'abc' to channel 4") before
  // Lua has been made aware of channel 4's existence.
  private int handshakeMessages = 0;
  private final CompletableFuture<Integer> channelIdFuture = new CompletableFuture<>();

  // All async operations we do to send information down to the HSM need to be ordered
  // with respect to this channel, so we chain together completable futures to make this
  // so.  Note that the lastFuture is instantiated per-channel, so we're only serializing
  // execution within a single channel.  Multiple channels can still interleave their
  // requests without issue.
  private CompletableFuture<Void> lastFuture = CompletableFuture.completedFuture(null);

  protected ChannelHandler(
      final ModuleServiceEndpoint endpoint,
      final StreamObserver<ChannelResponse> responseObserver) {
    this.endpoint = endpoint;
    this.responseObserver = responseObserver;
  }

  public CompletableFuture<Integer> getChannelId() {
    return channelIdFuture;
  }

  @Override
  public void onNext(final ChannelRequest clientChannelRequest) {
    lastFuture = lastFuture.thenCompose((unused) -> {
      try {
        if (channelId == null) {
          return initialize(clientChannelRequest);
        } else if (clientChannelRequest.getKindCase() != ChannelRequest.KindCase.CHANNEL_MESSAGE) {
          throw Status.fromCode(Code.INVALID_ARGUMENT)
              .withDescription("after first message, must only send channel messages").asException();
        } else {
          // We must 'thenAccept' here rather than 'thenAcceptAsync', because we must handleResponses in the order
          // that they were received from the HostQueue.  Otherwise, we run the risk that the output of messages
          // will be reordered by multiple requesters, which for encrypted (specifically KK) channels will break
          // the channel due to out-of-sync cipherstate.
          return endpoint.sendToHostQueue(
                  Request.buildChannelMessageRequest(processId, channelId,
                      clientChannelRequest.getChannelMessage().toByteArray()))
              .thenAccept(responses -> {
                try {
                  endpoint.handleResponses(responses);
                } catch (StatusException e) {
                  throw new CompletionException(e);
                }
                maybeCompleteHandshake();
              });
        }
      } catch (StatusException e) {
        logger.trace("Error handling client channel request", e);
        throw new CompletionException(e);
      }
    });
    lastFuture.whenComplete((unused, error) -> { if (error != null) complete(error); });
  }

  private CompletableFuture<Void> initialize(ChannelRequest request) throws StatusException {
    if (request.getKindCase() != KindCase.INIT) {
      throw Status.fromCode(Code.INVALID_ARGUMENT).withDescription("first message must specify process to attach to")
          .asException();
    }
    ChannelInit init = request.getInit();
    processId = endpoint.processId(init);
    Request hsmRequest;
    switch (init.getChannelType()) {
      case CHANNEL_TYPE_UNENCRYPTED:
        hsmRequest = Request.buildCreateRawChannelRequest(processId);
        handshakeMessages = 1;
        break;
      case CHANNEL_TYPE_CLIENT_NK:
        hsmRequest = Request.buildCreateClientNkChannelRequest(processId);
        handshakeMessages = 2;
        break;
      case CHANNEL_TYPE_CLIENT_KK_INITIATOR:
        hsmRequest = Request.buildCreateClientKkChannelInitRequest(processId);
        handshakeMessages = 2;
        break;
      case CHANNEL_TYPE_CLIENT_KK_RESPONDER:
        hsmRequest = Request.buildCreateClientKkChannelRespRequest(processId);
        handshakeMessages = 2;
        break;
      default:
        throw Status.fromCode(Code.UNIMPLEMENTED).asException();
    }
    return endpoint.sendToHostQueue(hsmRequest)
        .thenAccept(responses -> {
          try {
            if (responses.size() < 1 || !(responses.get(0) instanceof NewID)) {
              throw Status.fromCode(Code.INTERNAL).withDescription("channel create didn't return channel ID")
                  .asException();
            }
            maybeCompleteHandshake();
            channelId = responses.get(0).getChannelId();
            endpoint.registerChannelHandler(processId, channelId, this);
            responseObserver.onNext(ChannelResponse.newBuilder().setChannelId(channelId).build());
            endpoint.handleResponses(responses.subList(1, responses.size()));
          } catch (StatusException e) {
            throw new CompletionException(e);
          }
        });
  }

  @Override
  public void onError(final Throwable throwable) {
    lastFuture = lastFuture.thenRun(() -> complete(throwable));
  }

  private void complete(final Throwable throwable) {
    if (completed) return;
    completed = true;
    unregister();
    if (throwable != null) {
      logger.trace("Error received: p{} c{}", processId, channelId, throwable);
      channelIdFuture.completeExceptionally(throwable);
      responseObserver.onError(throwable);
    } else {
      logger.trace("Completing without error: p{} c{}", processId, channelId);
      channelIdFuture.completeExceptionally(Status.ABORTED.asException());
      responseObserver.onCompleted();
    }
  }

  void sendMessage(ByteString msg) {
    responseObserver.onNext(ChannelResponse.newBuilder().setChannelMessage(msg).build());
  }

  private static final Map<Integer, Code> codeFromInt = new HashMap<>();
  static {
    for (Code c : Code.values()) {
      codeFromInt.put(c.value(), c);
    }
  }

  void closeWithCode(int statusCode) {
    Code code = codeFromInt.get(statusCode);
    if (code == null) {
      code = Code.UNKNOWN;
    }
    closedByProcess = true;
    if (code == Code.OK) {
      onCompleted();
    } else {
      onError(Status.fromCode(code).asException());
    }
  }

  @Override
  public void onCompleted() {
    lastFuture = lastFuture.thenRun(() -> complete(null));
  }

  private void unregister() {
    if (processId != null && channelId != null) {
      endpoint.unregisterChannelHandler(processId, channelId);
      // async, we don't wait for this response.
      if (!closedByProcess) {
        endpoint.sendToHostQueue(Request.buildCloseChannelRequest(processId, channelId));
      }
    }
  }

  private void maybeCompleteHandshake() {
    if (handshakeMessages > 0 && --handshakeMessages == 0) {
      channelIdFuture.complete(channelId);
    }
  }
}
