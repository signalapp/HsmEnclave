/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.service;

import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import io.grpc.Context;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.Status.Code;
import io.grpc.StatusException;
import io.grpc.stub.StreamObserver;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import jakarta.annotation.PostConstruct;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import javax.annotation.Nullable;
import org.apache.commons.codec.binary.Hex;
import org.signal.hsmenclave.ModuleProto;
import org.signal.hsmenclave.ModuleProto.ChannelInit;
import org.signal.hsmenclave.ModuleProto.ChannelRequest;
import org.signal.hsmenclave.ModuleProto.ChannelType;
import org.signal.hsmenclave.ModuleProto.CrossProcessChannelCreateResponse;
import org.signal.hsmenclave.ModuleServiceGrpc;
import org.signal.hsmenclave.queue.HostQueue;
import org.signal.hsmenclave.queue.message.Request;
import org.signal.hsmenclave.queue.message.Response;
import org.signal.hsmenclave.queue.message.Response.NewID;
import org.signal.hsmenclave.queue.message.Response.ProcessHash;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@io.micronaut.context.annotation.Context
public class ModuleServiceEndpoint extends ModuleServiceGrpc.ModuleServiceImplBase {
  private static final Logger logger = LoggerFactory.getLogger(ModuleServiceEndpoint.class);

  /** Set of current process streams, by process ID.  Only one stream allowed per ID. */
  private final Map<Integer, ByteString> processIdToHash = new HashMap<>();
  private final Map<ByteString, Integer> processHashToId = new HashMap<>();
  /** Set of channel message streams:  channelMessengers[processId][channelId] */
  private final Map<Integer, Map<Integer, ChannelHandler>> channelHandlers = new HashMap<>();

  private final HostQueue hostQueue;

  public ModuleServiceEndpoint(final HostQueue hostQueue) {
    this.hostQueue = hostQueue;
  }

  @PostConstruct
  void start() throws StatusException {
    final List<Response> listResponses;
    try {
      listResponses = sendToHostQueue(Request.LIST_REQUEST).get();
    } catch (Exception e) {
      throw Status.fromThrowable(e).withDescription("Requesting list of processes").asException();
    }
    synchronized (this) {
      for (Response listResponse : listResponses) {
        if (!(listResponse instanceof Response.ProcessHash)) {
          throw Status.fromCode(Code.INTERNAL)
              .withDescription("Received non-process-hash response from HSM LIST request").asException();
        }
        ProcessHash ph = (ProcessHash) listResponse;
        ByteString hash = ByteString.copyFrom(ph.getPayload());
        processIdToHash.put(ph.getProcessId(), hash);
        processHashToId.put(hash, ph.getProcessId());
      }
    }
  }

  CompletableFuture<List<Response>> sendToHostQueue(Request request) {
    return hostQueue.sendRequest(request);
  }

  @VisibleForTesting
  synchronized void reset() throws Exception{
    hostQueue.resetHsm().get();
    processHashToId.clear();
    processIdToHash.clear();
    channelHandlers.clear();
  }

  private synchronized Optional<ChannelHandler> getChannelHandler(int processId, int channelId) {
    Map<Integer, ChannelHandler> processMessengers = channelHandlers.get(processId);
    if (processMessengers == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(processMessengers.get(channelId));
  }

  protected synchronized void registerChannelHandler(int processId, int channelId,
      ChannelHandler handler)
      throws StatusException {
    final Map<Integer, ChannelHandler> byChannel = channelHandlers
        .computeIfAbsent(processId, k -> new HashMap<>());
    if (byChannel.containsKey(channelId))
      throw Status.fromCode(Code.ALREADY_EXISTS).withDescription("channel ID already registered").asException();
    byChannel.put(channelId, handler);
  }

  protected synchronized void unregisterChannelHandler(int processId, int channelId) {
    final Map<Integer, ChannelHandler> byChannel = channelHandlers.get(processId);
    if (byChannel == null) return;
    byChannel.remove(channelId);
    if (byChannel.isEmpty()) channelHandlers.remove(processId);
  }

  /** Handle a list of responses, like those coming back from sendToHostQueue. */
  void handleResponses(List<Response> responses) throws StatusException {
    for (Response r : responses) {
      if (r instanceof Response.ChannelMessage) {
        Response.ChannelMessage cm = (Response.ChannelMessage) r;
        getChannelHandler(cm.getProcessId(), cm.getChannelId())
            .orElseThrow(() -> Status.fromCode(Code.NOT_FOUND).withDescription("channel not found").asException())
            .sendMessage(ByteString.copyFrom(cm.getPayload()));
      } else if (r instanceof Response.ChannelClose) {
        Response.ChannelClose cc = (Response.ChannelClose) r;
        getChannelHandler(cc.getProcessId(), cc.getChannelId())
            .orElseThrow(() -> Status.fromCode(Code.NOT_FOUND).withDescription("channel not found").asException())
            .closeWithCode(cc.statusCode());
      } else if (r instanceof Response.Error) {
        throw Status.fromCode(Code.INTERNAL).withDescription(r.toString()).asException();
      } else {
        throw Status.fromCode(Code.UNIMPLEMENTED).withDescription("unimplemented response type").asException();
      }
    }
  }

  @Override
  public StreamObserver<ModuleProto.ChannelRequest> channel(
      StreamObserver<ModuleProto.ChannelResponse> responseObserver) {
    return new ChannelHandler(this, responseObserver);
  }

  @Override
  public void processCreate(ModuleProto.ProcessCreateRequest request,
      StreamObserver<ModuleProto.ProcessCreateResponse> responseObserver) {
    try {
      ByteString hash = ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request.getLuaCode().toByteArray()));
      logger.info("Creating process with hash {}", Hex.encodeHexString(hash.toByteArray()));
      synchronized (this) {
        if (processHashToId.containsKey(hash)) {
          throw Status.fromCode(Code.ALREADY_EXISTS).withDescription("process ID or hash already exists").asException();
        }
      }
      List<Response> responses = sendToHostQueue(Request.buildCreateProcessRequest(request.getLuaCode().toByteArray())).get();
      if (responses.size() != 1 || !(responses.get(0) instanceof NewID)) {
        throw Status.fromCode(Code.INTERNAL).withDescription("process create returned invalid output").asException();
      }
      int processID = responses.get(0).getProcessId();
      synchronized (this) {
        processHashToId.put(hash, processID);
        processIdToHash.put(processID, hash);
      }
      responseObserver.onNext(ModuleProto.ProcessCreateResponse.newBuilder()
          .setProcessId(processID)
          .setCodeHash(hash)
          .build());
      responseObserver.onCompleted();
    } catch (Throwable t) {
      logger.warn("Failed to create process", t);
      responseObserver.onError(t);
    }
  }

  class IDHash {
    IDHash(Integer id, ByteString hash) {
      this.id = id;
      this.hash = hash;
    }
    Integer id;
    ByteString hash;
  }

  private synchronized IDHash idHash(@Nullable Integer id, @Nullable ByteString hash) throws StatusException {
    if (id != null && id != 0) {
      hash = processIdToHash.get(id);
      if (hash == null) {
        throw Status.fromCode(Code.NOT_FOUND).withDescription("process ID not found").asException();
      }
      return new IDHash(id, hash);
    } else if (hash != null && !hash.isEmpty()) {
      id = processHashToId.get(hash);
      if (id == null) {
        throw Status.fromCode(Code.NOT_FOUND).withDescription("process hash not found").asException();
      }
    } else {
      throw Status.fromCode(Code.INVALID_ARGUMENT).withDescription("no id or hash provided for process").asException();
    }
    return new IDHash(id, hash);
  }

  @Override
  public void processDestroy(ModuleProto.ProcessDestroyRequest request,
      StreamObserver<ModuleProto.ProcessDestroyResponse> responseObserver) {
    try {
      IDHash idHash = idHash(request.getProcessId(), request.getCodeHash());
      logger.info("Destroying process {} with hash {}", idHash.id, Hex.encodeHexString(idHash.hash.toByteArray()));
      List<Response> responses = sendToHostQueue(Request.buildDestroyProcessRequest(idHash.id)).get();
      if (!responses.isEmpty()) {
        throw Status.fromCode(Code.INTERNAL).withDescription("process create returned invalid output").asException();
      }
      synchronized (this) {
        processHashToId.remove(idHash.hash);
        processIdToHash.remove(idHash.id);
      }
      responseObserver.onNext(ModuleProto.ProcessDestroyResponse.newBuilder()
          .build());
      responseObserver.onCompleted();
    } catch (Throwable t) {
      logger.warn("Failed to destroy process", t);
      responseObserver.onError(t);
    }
  }

  @Override
  @ExecuteOn(TaskExecutors.IO)  // due to blocking on GRPC connection creation
  public void crossProcessChannelCreate(ModuleProto.CrossProcessChannelCreateRequest request,
      StreamObserver<ModuleProto.CrossProcessChannelCreateResponse> createResponse) {
    IDHash idHash;
    try {
      idHash = idHash(null, request.getCodeHash());
    } catch (Throwable t) {
      logger.warn("Failed to create cross-process channel", t);
      createResponse.onError(t);
      return;
    }
    logger.info("Cross-process connection started to {} from process {}:{}",
        request.getRemoteHostAddress(), idHash.id, Hex.encodeHexString(idHash.hash.toByteArray()));
    ManagedChannel channel = ManagedChannelBuilder
        .forTarget(request.getRemoteHostAddress())
        .usePlaintext()
        .build();
    ModuleServiceGrpc.ModuleServiceStub stub = ModuleServiceGrpc.newStub(channel);
    ChannelInit.Builder channelInit = ChannelInit.newBuilder();
    channelInit.setCodeHash(request.getCodeHash());

    try {
      // Wire up the local channel handler with the remote channel.  This is a little weird,
      // since these things need to exist already, so they can be referenced by the actual streams
      // we set up, but they don't have outputs yet.  We handle this by having the reverser be
      // created here, then setting its `outputToRequester` after it's referenced.
      // Luckily, we know that no messages will need to be passed until we send init messages on
      // associated channels, which we don't do until we're fully wired up.
      final ChannelReverser remoteResponseToLocalRequest = new ChannelReverser();
      final ChannelReverser localRequestToRemoteResponse = new ChannelReverser();
      // We want the .channel() stream to last longer than the local context of the RPC call we're
      // currently servicing, so we need to fork the current context.
      final StreamObserver<ChannelRequest> remoteSender = Context.current().fork().call(
          () -> stub.channel(remoteResponseToLocalRequest));
      final ChannelHandler localReceiver = new ChannelHandler(this, localRequestToRemoteResponse);
      remoteResponseToLocalRequest.outputToRequester(localReceiver);
      localRequestToRemoteResponse.outputToRequester(remoteSender);

      // Initiate remote as a responder, so it's waiting for a handshake
      remoteSender.onNext(ChannelRequest.newBuilder().setInit(
          channelInit.setChannelType(ChannelType.CHANNEL_TYPE_CLIENT_KK_RESPONDER)).build());
      // Initiate local as an initiator.  Since we've already attached the channels above,
      // when it sends a handshake message out, that message will go through to the remote
      // responder, and from that point on they're talking like they should.
      localReceiver.onNext(ChannelRequest.newBuilder().setInit(
          channelInit.setChannelType(ChannelType.CHANNEL_TYPE_CLIENT_KK_INITIATOR)).build());
      // Wait until the local receiver has handshake'd and we have a valid, working channel ID for it,
      // then call us done.
      localReceiver.getChannelId().whenCompleteAsync(
          (id, err) -> {
            if (err != null) {
              createResponse.onError(err);
            } else {
              createResponse.onNext(CrossProcessChannelCreateResponse.newBuilder()
                  .setLocalProcessId(idHash.id)
                  .setLocalChannelId(id)
                  .build());
              createResponse.onCompleted();
            }
          });
    } catch (Exception e) {
      logger.error("Failed to create cross-process connection", e);
      createResponse.onError(e);
    }
  }

  synchronized int processId(ChannelInit init) throws StatusException {
    switch (init.getProcCase()) {
      case PROCESS_ID:
        if (!processIdToHash.containsKey(init.getProcessId())) {
          throw Status.fromCode(Code.NOT_FOUND).withDescription("process ID not found").asException();
        }
        return init.getProcessId();
      case CODE_HASH:
        Integer processId = processHashToId.get(init.getCodeHash());
        if (processId == null) {
          throw Status.fromCode(Code.NOT_FOUND).withDescription("process ID not found").asException();
        }
        return processId;
      default:
        throw Status.fromCode(Code.INVALID_ARGUMENT).withDescription("invalid ChannelInit process identifier").asException();
    }
  }
}
