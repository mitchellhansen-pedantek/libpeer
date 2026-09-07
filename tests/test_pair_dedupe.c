// One pair per (local, remote): a remote candidate that is paired when it
// trickles in and again when the answer names it must not produce a second,
// identical pair — the duplicates fill AGENT_MAX_INPROGRESS with the same
// check and starve candidates paired later (embed-sdk bug report 1d44db37).

#include <stdio.h>
#include <string.h>

#include "agent.h"
#include "ice.h"

static int g_failures = 0;

#define CHECK(cond)                                          \
  do {                                                       \
    if (!(cond)) {                                           \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      g_failures++;                                          \
    }                                                        \
  } while (0)

static void make_addr(const char* ip, uint16_t port, Address* addr) {
  memset(addr, 0, sizeof(*addr));
  addr_from_string(ip, addr);
  addr_set_port(addr, port);
}

int main(void) {
  Agent agent;
  memset(&agent, 0, sizeof(agent));

  Address a;
  make_addr("10.0.0.5", 36770, &a);
  ice_candidate_create(&agent.local_candidates[0], 0, ICE_CANDIDATE_TYPE_HOST, &a);
  make_addr("10.0.0.5", 36771, &a);
  ice_candidate_create(&agent.local_candidates[1], 1, ICE_CANDIDATE_TYPE_SRFLX, &a);
  make_addr("10.0.0.5", 36772, &a);
  ice_candidate_create(&agent.local_candidates[2], 2, ICE_CANDIDATE_TYPE_RELAY, &a);
  agent.local_candidates_count = 3;

  make_addr("192.0.2.10", 62277, &a);
  ice_candidate_create(&agent.remote_candidates[0], 0, ICE_CANDIDATE_TYPE_SRFLX, &a);
  agent.remote_candidates_count = 1;

  // Trickled first: paired on arrival.
  agent_pair_remote_candidate(&agent, &agent.remote_candidates[0]);
  CHECK(agent.candidate_pairs_num == 3);

  // Then the answer names it: the bulk pairing must add nothing.
  agent_update_candidate_pairs(&agent);
  CHECK(agent.candidate_pairs_num == 3);

  // And pairing it a second time by the trickle path adds nothing either.
  agent_pair_remote_candidate(&agent, &agent.remote_candidates[0]);
  CHECK(agent.candidate_pairs_num == 3);

  // A genuinely new remote still pairs against every local.
  make_addr("10.0.0.184", 62277, &a);
  ice_candidate_create(&agent.remote_candidates[1], 1, ICE_CANDIDATE_TYPE_HOST, &a);
  agent.remote_candidates_count = 2;
  agent_pair_remote_candidate(&agent, &agent.remote_candidates[1]);
  CHECK(agent.candidate_pairs_num == 6);
  agent_update_candidate_pairs(&agent);
  CHECK(agent.candidate_pairs_num == 6);

  if (g_failures == 0) {
    printf("test_pair_dedupe: all checks passed\n");
  } else {
    printf("test_pair_dedupe: %d check(s) FAILED\n", g_failures);
  }
  return g_failures == 0 ? 0 : 1;
}
