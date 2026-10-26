/* SAE (Simultaneous Authentication of Equals), group 19 only. */
#ifndef _NET80211_IEEE80211_SAE_H_
#define _NET80211_IEEE80211_SAE_H_

#include <stdint.h>
#include <stddef.h>

#define IEEE80211_SAE_GROUP		19
#define IEEE80211_SAE_SCALAR_LEN	32
#define IEEE80211_SAE_ELEMENT_LEN	64
#define IEEE80211_SAE_COMMIT_LEN	(2 + 32 + 64)
#define IEEE80211_SAE_CONFIRM_LEN	(2 + 32)
#define IEEE80211_SAE_PMK_LEN		32
#define IEEE80211_SAE_PMKID_LEN		16
#define IEEE80211_SAE_MAX_PASSWORD_LEN	255
#define IEEE80211_SAE_MAX_TOKEN_LEN	256
#define IEEE80211_SAE_MAX_TOKEN_RETRIES	3

struct ieee80211_sae {
	uint8_t pwe[64];
	uint8_t own_rand[32];
	uint8_t own_scalar[32];
	uint8_t own_element[64];
	uint8_t peer_scalar[32];
	uint8_t peer_element[64];
	uint8_t kck[32];
	uint8_t pmk[32];
	uint8_t pmkid[16];
	uint16_t send_confirm;
	uint16_t peer_confirm;
	uint8_t own_addr[6];
	uint8_t peer_addr[6];
	uint8_t pwe_ready;
	uint8_t commit_ready;
	uint8_t peer_ready;
	uint8_t confirmed;
	uint8_t token[IEEE80211_SAE_MAX_TOKEN_LEN];
	uint16_t token_len;
	uint8_t token_retries;
#ifdef IEEE80211_SAE_TESTING
	int (*random)(void *, uint8_t *, size_t);
	void *random_arg;
#endif
};

#ifdef __cplusplus
extern "C" {
#endif

void ieee80211_sae_clear(struct ieee80211_sae *);
int ieee80211_sae_start(struct ieee80211_sae *, const uint8_t[6],
    const uint8_t[6], const uint8_t *, size_t);
int ieee80211_sae_new_commit(struct ieee80211_sae *, uint8_t[98]);
size_t ieee80211_sae_commit_length(const struct ieee80211_sae *);
int ieee80211_sae_set_token(struct ieee80211_sae *, const uint8_t *, size_t);
int ieee80211_sae_write_commit(struct ieee80211_sae *, uint8_t *, size_t);
int ieee80211_sae_process_commit(struct ieee80211_sae *, const uint8_t *,
    size_t);
int ieee80211_sae_write_confirm(struct ieee80211_sae *, uint8_t[34]);
int ieee80211_sae_check_confirm(struct ieee80211_sae *, const uint8_t *,
    size_t);

#ifdef IEEE80211_SAE_TESTING
void ieee80211_sae_test_rng(struct ieee80211_sae *,
    int (*)(void *, uint8_t *, size_t), void *);
int ieee80211_sae_test_pwe(struct ieee80211_sae *, const uint8_t[6],
    const uint8_t[6], const uint8_t *, size_t, uint8_t[64]);
int ieee80211_sae_test_commit(struct ieee80211_sae *, const uint8_t[32],
    const uint8_t[32], uint8_t[98]);
#endif

#ifdef __cplusplus
}
#endif
#endif
