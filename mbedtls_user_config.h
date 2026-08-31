/* mbedtls_user_config.h — libpeer's additions to mbedtls's default config.
 *
 * Included by mbedtls itself via MBEDTLS_USER_CONFIG_FILE (build_info.h), which
 * appends this to the stock mbedtls_config.h. Passed in from libpeer's
 * CMakeLists as a cache variable; mbedtls's own CMake turns it into the
 * compile definition.
 *
 * This replaces a build step that READ the vendored mbedtls_config.h,
 * string-replaced the commented-out define, and WROTE the file back into the
 * source tree. That had two faults beyond mutating a vendored dependency:
 * it left the submodule permanently dirty after any fresh configure, and the
 * variable was expanded unquoted, so CMake treated every `;` in the file as a
 * list separator and dropped it — 21 lines of collateral corruption for one
 * intended define, in a header the TLS stack is compiled against.
 */
#ifndef LIBPEER_MBEDTLS_USER_CONFIG_H
#define LIBPEER_MBEDTLS_USER_CONFIG_H

/* Thread safety for the SHARED crypto state.
 *
 * Every DtlsSrtp is configured against process-global material: one ctr_drbg
 * (mbedtls_ssl_conf_rng and the server cookie ctx) and one RSA key
 * (mbedtls_ssl_conf_own_cert). With MBEDTLS_THREADING_C off, the internal
 * mutexes in ctr_drbg.c and rsa.c compile out, so mbedtls_ctr_drbg_random
 * mutates its counter and AES context unguarded and mbedtls_rsa_private
 * mutates its blinding MPIs unguarded.
 *
 * That was safe while one reactor thread drove every peer_connection_loop, and
 * so every handshake. It is not: each lane now has its own worker, and the
 * datachannel pool means one viewer opens several lanes that handshake at the
 * same instant. Sharing a DRBG across those is duplicated ClientHello randoms
 * and ECDHE keys; sharing the RSA blinding cache is MPI corruption. This build
 * is DTLS server with an RSA cert (CONFIG_DTLS_USE_ECDSA 0), so the private-key
 * operation runs on every one of them. */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD

/* DTLS-SRTP key export. Required by dtls_srtp.c —
 * mbedtls_ssl_conf_dtls_srtp_protection_profiles() and
 * mbedtls_ssl_get_dtls_srtp_negotiation_result() do not exist without it, so
 * losing this define breaks WebRTC media encryption at the handshake rather
 * than at build time. */
#define MBEDTLS_SSL_DTLS_SRTP

#endif /* LIBPEER_MBEDTLS_USER_CONFIG_H */
