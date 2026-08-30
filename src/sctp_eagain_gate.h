#ifndef SCTP_EAGAIN_GATE_H_
#define SCTP_EAGAIN_GATE_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * sctp_eagain_gate — pure rate-limiting decision for the sctp_outgoing_data()
 * EAGAIN/EWOULDBLOCK path (sctp.c).
 *
 * A full SCTP send buffer under sustained backpressure is an EXPECTED
 * condition, not an error: usrsctp's socket is non-blocking by design, and at
 * least one caller (datachannel_hls.c's segment-export retry loop) polls
 * every 250us specifically so a stalled chunk resumes the instant the buffer
 * reopens. Logging (and querying SCTP_STATUS) on every one of those polls
 * turns ordinary congestion into up to ~4000 log lines/sec per stalled send —
 * enough to evict a 10k-line device diag ring buffer in under three seconds.
 *
 * This function decides only WHETHER an attempt should produce a log line;
 * it does no I/O and touches no global state, so it is testable without a
 * live SCTP association or a mocked clock singleton.
 *
 * Uses a SIGNED elapsed-time comparison against a MONOTONIC clock the caller
 * supplies. This is deliberate: a naive `now - last >= interval` on unsigned
 * types wraps to a huge value the instant `now` is not strictly ahead of
 * `last`, which reopens the gate on every call instead of none. That exact
 * failure mode broke sigshell's zero-fanout warning rate limit (see
 * sigshell.c history) — this gate is written so the same mistake cannot
 * reappear here.
 */

/*
 * last_log_ns:    CLOCK_MONOTONIC timestamp of the last emitted summary line,
 *                 in nanoseconds. 0 means "never logged" — the caller's state
 *                 starts zeroed (Sctp is calloc'd) and 0 is not a value
 *                 CLOCK_MONOTONIC can plausibly reuse mid-run.
 * now_ns:         CLOCK_MONOTONIC timestamp of the current attempt.
 * interval_ns:    minimum spacing between summary lines.
 * out_elapsed_ns: if non-NULL, receives the elapsed time since the last log
 *                 (0 on the very first call) — the caller reports this in the
 *                 summary line ("x123 in 4s").
 *
 * Returns true when this attempt should log (and the caller should update its
 * stored last_log_ns to now_ns): either this is the first occurrence, or at
 * least interval_ns has elapsed since the last log. A negative or
 * non-positive elapsed time (a clock that is not strictly monotonic, or two
 * calls landing at the same instant) never falsely satisfies the interval.
 */
bool sctp_eagain_gate_should_log(int64_t last_log_ns, int64_t now_ns,
                                  int64_t interval_ns, int64_t* out_elapsed_ns);

#endif  // SCTP_EAGAIN_GATE_H_
