/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Metrics;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.LinkedBlockingQueue;
import org.apache.commons.lang3.tuple.Pair;
import org.signal.hsmenclave.queue.message.Request;
import org.signal.hsmenclave.queue.message.Response;
import org.signal.hsmenclave.queue.message.Response.Error;
import org.signal.hsmenclave.queue.message.Response.ResetHsm;
import org.signal.hsmenclave.queue.message.Response.ResponseMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HostQueue provides HSM communication to an OsConnection backend, with the
 * following guarantees:
 *   1) At most CONCURRENT_RUNNING_REQUESTS will be outstanding to the HSM at any time
 *   2) Sends will all be serial
 *   3) Receives will all be serial, and will be in the order of sends
 */
@Singleton
public class HostQueue {
  private static final Logger logger = LoggerFactory.getLogger(HostQueue.class);
  private static final int CONCURRENTLY_RUNNING_REQUESTS = 3;
  private final OsConnection connection;

  private volatile boolean running;
  private final Thread senderThread;
  private final Thread receiverThread;

  private final BlockingQueue<Pair<Request, CompletableFuture<List<Response>>>> pendingRequests = new LinkedBlockingQueue<>();
  private final BlockingQueue<Object> pendingRefs = new ArrayBlockingQueue<>(CONCURRENTLY_RUNNING_REQUESTS - 1);
  private final BlockingQueue<CompletableFuture<List<Response>>> pendingResponses = new LinkedBlockingQueue<>();

  public HostQueue(final OsConnection connection) {
    this.connection = connection;

    this.senderThread = new Thread(this::processRequests, "HostQueueSender");
    this.receiverThread = new Thread(this::processResponses, "HostQueueReceiver");
    this.running = true;

    Gauge.builder("HostQueue.pendingRequestQueueSize", pendingRequests, BlockingQueue::size)
         .register(Metrics.globalRegistry);
    Gauge.builder("HostQueue.pendingRefsQueueSize", pendingRefs, BlockingQueue::size)
         .register(Metrics.globalRegistry);
    Gauge.builder("HostQueue.pendingResponsesQueueSize", pendingResponses, BlockingQueue::size)
         .register(Metrics.globalRegistry);

    this.senderThread.start();
    this.receiverThread.start();
  }

  public CompletableFuture<List<Response>> sendRequest(final Request request) {
    if (!running) {
      throw new IllegalStateException("sending request while not running");
    }
    final CompletableFuture<List<Response>> future = new CompletableFuture<>();
    pendingRequests.offer(Pair.of(request, future));

    return future;
  }

  private void requestStop() {
    this.running = false;
    this.senderThread.interrupt();
    this.receiverThread.interrupt();
  }

  public void stop() throws InterruptedException {
    requestStop();
    this.senderThread.join();
    this.receiverThread.join();
  }

  public CompletableFuture<ResetHsm> resetHsm() {
    return sendRequest(Request.RESET_REQUEST)
        .thenApply(x -> {
          if (x.size() != 1) throw new CompletionException(new OsException("wanted one response from RESET, got " + x.size()));
          Response r = x.get(0);
          if (r instanceof ResetHsm) return ((ResetHsm) r);
          if (r instanceof Error) throw new CompletionException(new OsException("ERR: " + r));
          throw new CompletionException(new OsException("unexpected type returned from RESET"));
        });
  }

  private void processRequests() {
    while (running) {
      final Request request;
      final CompletableFuture<List<Response>> future;

      try {
        final Pair<Request, CompletableFuture<List<Response>>> pair = pendingRequests.take();

        request = pair.getLeft();
        future = pair.getRight();
      } catch (final InterruptedException e) {
        continue;
      }

      try {
        logger.trace("Sending {}", request);
        final Object ref = connection.send(request.toByteArray());
        logger.trace("Got ref {}, {} before me", ref, this.pendingRefs.size());
        this.pendingRefs.put(ref);
        if (future != null) {
          this.pendingResponses.put(future);
        }
      } catch (Exception e) {
        logger.warn("Error processing request", e);
        future.completeExceptionally(e);
        continue;
      }
    }
  }
  private void processResponses() {
    while (running) {
      final CompletableFuture<List<Response>> future;
      try {
        future = pendingResponses.take();
      } catch (final InterruptedException e) {
        continue;
      }

      final List<Response> responses = new ArrayList<>();
      try {
        int expectedResponses = 1;
        while (running && expectedResponses > 0) {
          final Object ref;
          try {
            ref = pendingRefs.take();
          } catch (InterruptedException e) {
            continue;
          }
          logger.trace("Waiting for {}", ref);
          final Response response = Response.fromBytes(connection.receive(ref));
          logger.trace("Received {}", response);
          if (response instanceof ResponseMessages) {
            expectedResponses = ((ResponseMessages) response).getResponseMessageCount();
            for (int i = 0; i < expectedResponses; i++) {
              while (running) {
                try {
                  pendingRequests.put(Pair.of(Request.buildPollRequest(), null));
                } catch (InterruptedException e) {
                  continue;
                }
                break;
              }
            }
          } else {
            responses.add(response);
            expectedResponses--;
          }
        }
      } catch (OsException e) {
        logger.warn("Error processing response", e);
        future.completeExceptionally(e);
        continue;
      } catch (Exception e) {
        logger.error("Error in receive thread, shutting down", e);
        future.completeExceptionally(e);

        // We've got an exception that this thread can't handle.  Stop this thread,
        // then mark all current pending futures as failed.  After requestStop(),
        // future calls to sendRequest will fail, so this means that all futures,
        // past and future, will correctly fail exceptionally.
        requestStop();
        CompletableFuture<List<Response>> remainingFuture = pendingResponses.poll();
        while (remainingFuture != null) {
          remainingFuture.completeExceptionally(e);
          remainingFuture = pendingResponses.poll();
        }
        return;  // kill this thread
      }

      logger.trace("Responding with {}", responses);
      future.complete(responses);
    }
  }
}
