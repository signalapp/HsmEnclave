/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.service;

import io.grpc.stub.StreamObserver;
import org.signal.hsmenclave.ModuleProto.ChannelRequest;
import org.signal.hsmenclave.ModuleProto.ChannelResponse;
import org.signal.hsmenclave.ModuleProto.ChannelResponse.KindCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.concurrent.atomic.AtomicReference;

/** Makes a StreamObserver{ChannelRequest} into a StreamObserver{ChannelResponse}
 *
 * Once a ChannelRequest stream has been initiated, it's no different from a ChannelResponse stream;
 * they both just send messages as byte buffers back and forth.  When we create KK connections,
 * we establish a connection remotely and locally, and both of these need to be reversed as messages
 * coming up from the HSM as responses go out remotely as requests, and come in from remote as responses
 * and must be sent down to the HSM as requests.
 */
public class ChannelReverser implements StreamObserver<ChannelResponse> {
  private static final Logger logger = LoggerFactory.getLogger(ChannelReverser.class);
  final AtomicReference<StreamObserver<ChannelRequest>> requester = new AtomicReference<>();

  ChannelReverser() {}

  void outputToRequester(StreamObserver<ChannelRequest> requester) {
    if (!this.requester.compareAndSet(null, requester)) {
      throw new AssertionError("requester already set");
    }
  }

  @Override
  public void onNext(final ChannelResponse channelResponse) {
    if (!channelResponse.getKindCase().equals(KindCase.CHANNEL_MESSAGE)) return;
    requester.get().onNext(ChannelRequest.newBuilder()
        .setChannelMessage(channelResponse.getChannelMessage())
        .build());
  }

  @Override
  public void onError(final Throwable throwable) {
    logger.warn("Error in reverser", throwable);
    requester.get().onError(throwable);
  }

  @Override
  public void onCompleted() {
    requester.get().onCompleted();
  }
}
