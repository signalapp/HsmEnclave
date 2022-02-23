/*
 * Copyright 2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.hsmenclave.queue;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.southernstorm.noise.protocol.CipherStatePair;
import com.southernstorm.noise.protocol.HandshakeState;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import jakarta.inject.Inject;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.signal.hsmenclave.TestUtil;
import org.signal.hsmenclave.queue.message.Request;
import org.signal.hsmenclave.queue.message.Response;
import org.signal.hsmenclave.queue.message.Response.ChannelMessage;
import org.signal.hsmenclave.queue.message.Response.NewID;
import org.signal.hsmenclave.queue.message.Response.ResetHsm;

@MicronautTest
public class IntegrationTest {

  @Inject
  private HostQueue hostQueue;

  @BeforeEach
  void resetHsmBeforeTest() throws Exception {
    hostQueue.sendRequest(Request.RESET_REQUEST).get();
  }

  private static ByteBuffer bb(String s) {
    return ByteBuffer.wrap(s.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void runHsmAndInteract() throws Exception {
    final byte[] code = TestUtil.getResourceBytes(getClass(), "echo_n_times.lua");
    List<CompletableFuture<List<Response>>> futures = new ArrayList<>();
    futures.add(hostQueue.sendRequest(Request.buildCreateProcessRequest(code)));
    futures.add(hostQueue.sendRequest(Request.buildCreateRawChannelRequest(1)));
    futures.add(hostQueue.sendRequest(Request.buildCreateProcessRequest(code)));
    futures.add(hostQueue.sendRequest(Request.buildCreateRawChannelRequest(2)));
    futures.add(hostQueue.sendRequest(Request.buildChannelMessageRequest(1, 1, "abc".getBytes(StandardCharsets.UTF_8))));
    futures.add(hostQueue.sendRequest(Request.buildChannelMessageRequest(1, 1, "def".getBytes(StandardCharsets.UTF_8))));
    futures.add(hostQueue.sendRequest(Request.buildChannelMessageRequest(1, 1, "ghi".getBytes(StandardCharsets.UTF_8))));
    futures.add(hostQueue.sendRequest(Request.buildChannelMessageRequest(2, 1, "jkl".getBytes(StandardCharsets.UTF_8))));
    futures.add(hostQueue.sendRequest(Request.buildChannelMessageRequest(2, 1, "mno".getBytes(StandardCharsets.UTF_8))));
    assertEquals(List.of(new NewID(1, 0)), futures.get(0).get());
    assertEquals(List.of(new NewID(1, 1)), futures.get(1).get());
    assertEquals(List.of(new NewID(2, 0)), futures.get(2).get());
    assertEquals(List.of(new NewID(2, 1)), futures.get(3).get());
    assertEquals(List.of(new ChannelMessage(1, 1, bb("abc1"))), futures.get(4).get());
    assertEquals(List.of(
        new ChannelMessage(1, 1, bb("def2")),
        new ChannelMessage(1, 1, bb("def2"))),
        futures.get(5).get());
    assertEquals(List.of(
        new ChannelMessage(1, 1, bb("ghi3")),
        new ChannelMessage(1, 1, bb("ghi3")),
        new ChannelMessage(1, 1, bb("ghi3"))),
        futures.get(6).get());
    assertEquals(List.of(new ChannelMessage(2, 1, bb("jkl1"))), futures.get(7).get());
    assertEquals(List.of(
        new ChannelMessage(2, 1, bb("mno2")),
        new ChannelMessage(2, 1, bb("mno2"))),
        futures.get(8).get());
  }

  @Test
  void resetHsm() throws Exception {
    final byte[] code = TestUtil.getResourceBytes(getClass(), "echo_n_times.lua");
    List<CompletableFuture<List<Response>>> futures = new ArrayList<>();
    futures.add(hostQueue.sendRequest(Request.buildCreateProcessRequest(code)));
    CompletableFuture<ResetHsm> reset = hostQueue.resetHsm();
    futures.add(hostQueue.sendRequest(Request.buildCreateRawChannelRequest(1)));
    assertEquals(List.of(new NewID(1, 0)), futures.get(0).get());
    // public key of [0u8; 32]
    byte[] expectedPublicKey = Hex.decodeHex("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74");
    assertEquals(new Response.ResetHsm(0, 0, ByteBuffer.wrap(expectedPublicKey)), reset.get());
    // This should error out, since the process no longer exists.
    List<Response> responses = futures.get(1).get();
    assertEquals(1, responses.size());
    assertTrue(responses.get(0) instanceof Response.Error);

  }

  byte[] bufferToBytes(ByteBuffer bb) {
    byte[] out = new byte[bb.remaining()];
    bb.slice().get(out);
    return out;
  }

  @Test
  void testNoiseClient() throws Exception {
    final byte[] code = TestUtil.getResourceBytes(getClass(), "echo_n_times.lua");
    assertEquals(List.of(new NewID(1, 0)), hostQueue.sendRequest(Request.buildCreateProcessRequest(code)).get());
    assertEquals(List.of(new NewID(1, 1)), hostQueue.sendRequest(Request.buildCreateClientNkChannelRequest(1)).get());

    // Initial handshake send
    HandshakeState handshake = new HandshakeState("Noise_NK_25519_ChaChaPoly_SHA256", HandshakeState.INITIATOR);
    handshake.getRemotePublicKey().setPublicKey(Hex.decodeHex("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"), 0);
    final byte[] codeHash = MessageDigest.getInstance("SHA-256").digest(code);
    final byte[] handshakeMessage = new byte[64 + codeHash.length];
    handshake.start();
    int handshakeMessageSize = handshake.writeMessage(handshakeMessage, 0, codeHash, 0, codeHash.length);
    final List<Response> handshakeResp = hostQueue.sendRequest(
        Request.buildChannelMessageRequest(1, 1, ByteBuffer.wrap(handshakeMessage, 0, handshakeMessageSize))).get();

    // Initial handshake receive
    assertEquals(handshakeResp.size(), 1);
    assertTrue(handshakeResp.get(0) instanceof Response.ChannelMessage);
    byte[] handshakeResponseMessage = bufferToBytes(((ChannelMessage) handshakeResp.get(0)).getPayload());
    final byte[] handshakeResponsePayload = new byte[handshakeResponseMessage.length];
    int handshakeResponsePayloadSize = handshake.readMessage(handshakeResponseMessage, 0, handshakeResponseMessage.length, handshakeResponsePayload, 0);
    assertArrayEquals(bufferToBytes(ByteBuffer.wrap(handshakeResponsePayload, 0, handshakeResponsePayloadSize)), codeHash);
    CipherStatePair transport = handshake.split();

    // Initial payload send
    byte[] toSend = "ping".getBytes(StandardCharsets.UTF_8);
    byte[] sendCipherText = new byte[toSend.length + 16];
    assertEquals(sendCipherText.length, transport.getSender().encryptWithAd(null, toSend, 0, sendCipherText, 0, toSend.length));
    final List<Response> sendResp = hostQueue.sendRequest(
        Request.buildChannelMessageRequest(1, 1, ByteBuffer.wrap(sendCipherText))).get();

    // Initial payload recv
    assertEquals(sendResp.size(), 1);
    assertTrue(sendResp.get(0) instanceof Response.ChannelMessage);
    byte[] recvCipherText = bufferToBytes(((ChannelMessage) sendResp.get(0)).getPayload());
    byte[] expected = "ping1".getBytes(StandardCharsets.UTF_8);
    byte[] recvPlainText = new byte[expected.length];
    assertEquals(expected.length, transport.getReceiver().decryptWithAd(null, recvCipherText, 0, recvPlainText, 0, recvCipherText.length));
    assertArrayEquals(expected, recvPlainText);
  }
}
