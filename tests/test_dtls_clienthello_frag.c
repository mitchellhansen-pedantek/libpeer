// A ClientHello fragment that arrives without its offset=0 twin must not be
// handed to mbedtls as if it were a whole handshake message.
//
// Field incident (bug report a655c70e): two live grid tiles dropped, and every
// reconnect attempt then died in DTLS. The gateway logged, per attempt:
//
//   ClientHello fragmented: offset=1383, len=108, total=1491
//   Fragment mismatch, resetting
//   failed! mbedtls_ssl_handshake returned -0x7300   (SSL_DECODE_ERROR)
//   no remote fingerprint
//   DTLS handshake failed with error -1, connection failed
//
// The browser's cookie-bearing second ClientHello (1491 bytes, msg_seq=1) was
// split into offset=0/len=1383 and offset=1383/len=108, and the first fragment
// was lost on the relay path. A record whose handshake header says "bytes
// 1383..1491 of a 1491-byte message" must never reach mbedtls: it parses such a
// record as a whole ClientHello, gets garbage, and fails the connection — which
// no DTLS retransmission can undo.
//
// So the contract this pins down is that reassembly holds every fragment it is
// given until the message is fully covered, in any arrival order, and hands
// mbedtls nothing before then.
//
// This drives peer_connection.c (included below, since the reassembler is
// static inside the mbedtls BIO recv callback) over a real UDP socket.

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "peer.h"
#include "peer_connection.c"

static int g_failures = 0;

#define CHECK(cond)                                          \
  do {                                                       \
    if (!(cond)) {                                           \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      g_failures++;                                          \
    }                                                        \
  } while (0)

// One DTLS handshake record carrying one ClientHello fragment, laid out exactly
// as the header comment in peer_connection.c describes.
static int build_ch_fragment(uint8_t* out, uint16_t msg_seq, uint32_t total_len, uint32_t frag_offset, uint32_t frag_len) {
  uint32_t rec_payload = DTLS_HANDSHAKE_HEADER_LEN + frag_len;

  out[0] = DTLS_CONTENT_TYPE_HANDSHAKE;
  out[1] = 0xfe;  // DTLS 1.2 on the wire
  out[2] = 0xfd;
  out[3] = 0x00;  // epoch 0
  out[4] = 0x00;
  memset(out + 5, 0, 6);       // sequence number
  out[10] = (uint8_t)msg_seq;  // vary it so records are distinguishable
  out[11] = (rec_payload >> 8) & 0xFF;
  out[12] = rec_payload & 0xFF;

  uint8_t* hs = out + DTLS_RECORD_HEADER_LEN;
  hs[0] = DTLS_HANDSHAKE_TYPE_CLIENT_HELLO;
  write_uint24_be(hs + 1, total_len);
  hs[4] = (msg_seq >> 8) & 0xFF;
  hs[5] = msg_seq & 0xFF;
  write_uint24_be(hs + 6, frag_offset);
  write_uint24_be(hs + 9, frag_len);

  // Fragment body: a byte pattern keyed to its offset, so a misassembled
  // message is visible rather than silently plausible.
  for (uint32_t i = 0; i < frag_len; i++) {
    hs[DTLS_HANDSHAKE_HEADER_LEN + i] = (uint8_t)((frag_offset + i) & 0xFF);
  }

  return DTLS_RECORD_HEADER_LEN + rec_payload;
}

// Put one record on the wire and pump the shipped BIO recv callback once.
static int feed(PeerConnection* pc, int tx_fd, const struct sockaddr_in* dst, const uint8_t* rec, int rec_len, uint8_t* out, size_t out_len) {
  ssize_t sent = sendto(tx_fd, rec, rec_len, 0, (const struct sockaddr*)dst, sizeof(*dst));
  if (sent != rec_len) {
    printf("FAIL: sendto wrote %zd of %d bytes\n", sent, rec_len);
    g_failures++;
    return -1;
  }
  return peer_connection_dtls_srtp_recv(&pc->dtls_srtp, out, out_len);
}

int main(void) {
  peer_init();

  PeerConfiguration config;
  memset(&config, 0, sizeof(config));
  config.datachannel = DATA_CHANNEL_STRING;
  config.video_codec = CODEC_H264;
  config.audio_codec = CODEC_OPUS;

  PeerConnection* pc = peer_connection_create(&config);
  if (!pc) {
    printf("FAIL: peer_connection_create returned NULL\n");
    return 1;
  }

  // The reassembler is only reached from the CONNECTED-state handshake path,
  // and only when nothing is sitting in the single-shot agent_ret cache.
  pc->state = PEER_CONNECTION_CONNECTED;
  pc->agent_ret = 0;
  pc->dtls_srtp.user_data = pc;

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(pc->agent.udp_sockets[0].bind_addr.port);

  int tx_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (tx_fd < 0) {
    printf("FAIL: could not open sender socket\n");
    return 1;
  }

  uint8_t rec[2048];
  uint8_t out[4096];
  int n;

  // ── ClientHello #1: 1459 bytes, msg_seq 0, both fragments arrive ─────────
  // This is the path that works, and it is what the gateway logged five times
  // over while the browser retransmitted. Establish it as the baseline.
  n = build_ch_fragment(rec, 0, 1459, 0, 1383);
  CHECK(feed(pc, tx_fd, &dst, rec, n, out, sizeof(out)) == MBEDTLS_ERR_SSL_WANT_READ);

  n = build_ch_fragment(rec, 0, 1459, 1383, 76);
  int reassembled = feed(pc, tx_fd, &dst, rec, n, out, sizeof(out));
  CHECK(reassembled == DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1459);
  if (reassembled > DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN) {
    const uint8_t* hs = out + DTLS_RECORD_HEADER_LEN;
    CHECK(read_uint24_be(hs + 1) == 1459);  // total length
    CHECK(read_uint24_be(hs + 6) == 0);     // fragment offset: a whole message
    CHECK(read_uint24_be(hs + 9) == 1459);  // fragment length
  }

  // ── The incident: ClientHello #2, msg_seq 1, offset=0 fragment lost ──────
  // Only the tail arrives, so there is no complete ClientHello to hand over
  // and nothing may be handed over.
  n = build_ch_fragment(rec, 1, 1491, 1383, 108);
  int orphan = feed(pc, tx_fd, &dst, rec, n, out, sizeof(out));

  CHECK(orphan == MBEDTLS_ERR_SSL_WANT_READ);
  if (orphan > 0) {
    const uint8_t* hs = out + DTLS_RECORD_HEADER_LEN;
    printf("  handed mbedtls %d bytes: type=%u total=%u seq=%u frag_off=%u frag_len=%u\n", orphan, hs[0],
           read_uint24_be(hs + 1), (unsigned)((hs[4] << 8) | hs[5]), read_uint24_be(hs + 6), read_uint24_be(hs + 9));
    CHECK(read_uint24_be(hs + 6) == 0);  // never a mid-message fragment
  }

  // The tail was held, not discarded, so the peer's retransmit of the missing
  // fragment alone completes the message — recovery does not require the whole
  // flight to come again.
  n = build_ch_fragment(rec, 1, 1491, 0, 1383);
  int recovered = feed(pc, tx_fd, &dst, rec, n, out, sizeof(out));
  CHECK(recovered == DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1491);
  if (recovered == DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1491) {
    const uint8_t* body = out + DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN;
    CHECK(body[0] == 0x00);                       // first byte of the message
    CHECK(body[1383] == (uint8_t)(1383 & 0xFF));  // first byte of the held tail
    CHECK(body[1490] == (uint8_t)(1490 & 0xFF));  // last byte of the message
  }

  // ── The same orphan while an unrelated message is being assembled ────────
  // A fragment belonging to a different message must not be judged against the
  // one in progress.
  n = build_ch_fragment(rec, 2, 1459, 0, 1383);
  CHECK(feed(pc, tx_fd, &dst, rec, n, out, sizeof(out)) == MBEDTLS_ERR_SSL_WANT_READ);

  n = build_ch_fragment(rec, 3, 1491, 1383, 108);
  int orphan_mid = feed(pc, tx_fd, &dst, rec, n, out, sizeof(out));
  CHECK(orphan_mid == MBEDTLS_ERR_SSL_WANT_READ);

  // ── Out of order, nothing lost ───────────────────────────────────────────
  // UDP may deliver a flight's fragments in either order. Reassembly must not
  // depend on offset=0 arriving first — this case has no loss at all and still
  // has to produce the message.
  n = build_ch_fragment(rec, 4, 1459, 1383, 76);
  CHECK(feed(pc, tx_fd, &dst, rec, n, out, sizeof(out)) == MBEDTLS_ERR_SSL_WANT_READ);

  n = build_ch_fragment(rec, 4, 1459, 0, 1383);
  int reordered = feed(pc, tx_fd, &dst, rec, n, out, sizeof(out));
  CHECK(reordered == DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1459);
  if (reordered == DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1459) {
    const uint8_t* body = out + DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN;
    CHECK(body[0] == 0x00);                       // first byte of the message
    CHECK(body[1383] == (uint8_t)(1383 & 0xFF));  // first byte of the tail
    CHECK(body[1458] == (uint8_t)(1458 & 0xFF));  // last byte of the message
  }

  // ── Overlapping fragments must not be counted twice ──────────────────────
  // Completion is a question of which bytes arrived, not how many fragment
  // lengths add up: 0..1383 and 700..776 sum to exactly 1459 while 1383..1459
  // was never delivered. Counting the sum ships that hole to mbedtls inside a
  // ClientHello that looks well formed.
  n = build_ch_fragment(rec, 5, 1459, 0, 1383);
  CHECK(feed(pc, tx_fd, &dst, rec, n, out, sizeof(out)) == MBEDTLS_ERR_SSL_WANT_READ);

  n = build_ch_fragment(rec, 5, 1459, 700, 76);
  int holed = feed(pc, tx_fd, &dst, rec, n, out, sizeof(out));
  CHECK(holed == MBEDTLS_ERR_SSL_WANT_READ);  // 1383..1459 is still missing
  if (holed > 0) {
    printf("  completed a message with a 76-byte hole at 1383..1459\n");
  }

  // And the hole, once filled, completes it.
  n = build_ch_fragment(rec, 5, 1459, 1383, 76);
  CHECK(feed(pc, tx_fd, &dst, rec, n, out, sizeof(out)) ==
        DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1459);

  // ── The e2e fault injector induces exactly this ─────────────────────────
  // peer_connection_test_arm_clienthello_drop() is what the
  // "drop_clienthello_head" MQTT control action arms, so the e2e reproducer
  // and this unit test exercise one mechanism. If the hook stopped dropping,
  // the e2e would quietly prove nothing; this fails instead.
  peer_connection_test_arm_clienthello_drop(1);

  n = build_ch_fragment(rec, 6, 1491, 0, 1383);
  CHECK(feed(pc, tx_fd, &dst, rec, n, out, sizeof(out)) == MBEDTLS_ERR_SSL_WANT_READ);

  // The tail arrives with no head — the field shape.
  n = build_ch_fragment(rec, 6, 1491, 1383, 108);
  CHECK(feed(pc, tx_fd, &dst, rec, n, out, sizeof(out)) == MBEDTLS_ERR_SSL_WANT_READ);

  // The peer retransmits its flight and the message completes, head and tail
  // both intact.
  n = build_ch_fragment(rec, 6, 1491, 0, 1383);
  int after_drop = feed(pc, tx_fd, &dst, rec, n, out, sizeof(out));
  CHECK(after_drop == DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1491);
  if (after_drop == DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN + 1491) {
    const uint8_t* body = out + DTLS_RECORD_HEADER_LEN + DTLS_HANDSHAKE_HEADER_LEN;
    CHECK(body[0] == 0x00);
    CHECK(body[1383] == (uint8_t)(1383 & 0xFF));
    CHECK(body[1490] == (uint8_t)(1490 & 0xFF));
  }

  close(tx_fd);
  peer_connection_destroy(pc);
  peer_deinit();

  if (g_failures == 0) {
    printf("test_dtls_clienthello_frag: all checks passed\n");
  } else {
    printf("test_dtls_clienthello_frag: %d check(s) FAILED\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
