#include "sctp_eagain_gate.h"

bool sctp_eagain_gate_should_log(int64_t last_log_ns, int64_t now_ns,
                                  int64_t interval_ns, int64_t* out_elapsed_ns) {
  if (last_log_ns == 0) {
    if (out_elapsed_ns) *out_elapsed_ns = 0;
    return true; /* first occurrence: surface backpressure onset immediately */
  }

  int64_t elapsed_ns = now_ns - last_log_ns; /* signed: cannot wrap on a
                                                 backwards or equal reading */
  if (out_elapsed_ns) *out_elapsed_ns = elapsed_ns;

  return elapsed_ns >= interval_ns;
}
