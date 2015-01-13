/*
 * $FreeBSD: src/sys/crypto/rc4/rc4.h,v 1.2.2.1 2000/04/18 04:48:32 archie Exp $
 */

#ifndef _SYS_CRYPTO_RC4_RC4_H_
#define _SYS_CRYPTO_RC4_RC4_H_

struct rc4_state {
	u_char	perm[256];
	u_char	index1;
	u_char	index2;
};

extern void rc4_init(struct rc4_state *state, const u_char *key, int keylen);
extern void rc4_crypt(struct rc4_state *state,
		const u_char *inbuf, u_char *outbuf, int buflen);

#endif
