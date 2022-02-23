/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.signal.hsmenclave.queue.message.Request;
import org.signal.hsmenclave.queue.message.Response;
import org.signal.hsmenclave.queue.message.Response.ChannelMessage;
import org.signal.hsmenclave.queue.message.Response.ResponseMessages;

class HostQueueTest {
  @Test
  void testHostJobQueue() throws Exception {
    OsConnection conn = Mockito.mock(OsConnection.class);
    HostQueue h = new HostQueue(conn);
    Request req1 = Request.buildChannelMessageRequest(1, 1, new byte[0]);
    Response resp1n = new ResponseMessages(0, 0, 3);
    Response resp11 = new ChannelMessage(1, 2, ByteBuffer.wrap(new byte[]{1}));
    Response resp12 = new ChannelMessage(1, 3, ByteBuffer.wrap(new byte[]{1, 2}));
    Response resp13 = new ChannelMessage(1, 4, ByteBuffer.wrap(new byte[]{1, 2, 3}));
    // Request 2 has 1 response
    Request req2 = Request.buildChannelMessageRequest(2, 1, new byte[0]);
    Response resp21 = new ChannelMessage(1, 2, ByteBuffer.wrap(new byte[]{1}));
    // Request 3 has no responses
    Request req3 = Request.buildChannelMessageRequest(2, 1, new byte[0]);
    Response resp31 = new ResponseMessages(0, 0, 0);

    // These are our initial job, which returned 4 results.
    when(conn.send(Mockito.any())).thenReturn(Long.valueOf(0));
    when(conn.receive(Long.valueOf(0))).thenReturn(
        resp1n.toByteArray(),
        resp11.toByteArray(),
        resp12.toByteArray(),
        resp13.toByteArray(),
        resp21.toByteArray(),
        resp31.toByteArray());
    final CompletableFuture<List<Response>> j1 = h.sendRequest(req1);
    final CompletableFuture<List<Response>> j2 = h.sendRequest(req2);
    final CompletableFuture<List<Response>> j3 = h.sendRequest(req3);
    assertEquals(List.of(resp11, resp12, resp13), j1.get());
    assertEquals(List.of(resp21), j2.get());
    assertEquals(List.of(), j3.get());
    h.stop();
  }

  @Test
  void testHsmReturnsInvalidData() throws Exception {
    OsConnection conn = Mockito.mock(OsConnection.class);
    HostQueue h = new HostQueue(conn);
    Request req1 = Request.buildChannelMessageRequest(1, 1, new byte[0]);
    when(conn.send(Mockito.any())).thenReturn(Long.valueOf(0));
    when(conn.receive(Long.valueOf(0))).thenReturn(new byte[0]);
    final CompletableFuture<List<Response>> j1 = h.sendRequest(req1);
    final Exception e = assertThrows(ExecutionException.class, j1::get);
    assertTrue(e.getCause() instanceof IllegalArgumentException);
  }
}
