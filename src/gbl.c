#include <stdio.h>
#include <syslog.h>
#include "gbl.h"
#include "md5.h"
#include "rc4.h"
#include "strl.h"

gbl *gbl_list = NULL;

gbl *
gbl_new(const char *one, const char *two)
{
        gbl *g;

        if ((g = (gbl *)calloc(1, sizeof(gbl))) == NULL)
                return NULL;

        if (gbl_list) {
                g->next = gbl_list;
                gbl_list->prev = g;
        }
        gbl_list = g;

        g->one = lstrdup(one);
        g->two = lstrdup(two);

        return g;
}

void
gbl_del(gbl *g)
{
        if (gbl_list == g)
                gbl_list = (g->next ? g->next : NULL);
        if (g->prev != NULL)
                g->prev->next = g->next;
        if (g->next)
                g->next->prev = g->prev;

	free(g->one);
	free(g->two);
        free(g);
}

int
gbl_parse_list(const char *filename)
{
	char buf[GBLBUF], *ptr;
	FILE *fd;

	if (!(fd = fopen(filename, "r")))
		err(1, "Unable to open google blacklist %s", filename);

	while (fgets(buf, GBLBUF, fd)) {
		if (strlen(buf) < 40 || buf[33] != '\t')
			continue;
		buf[33] = 0;
		if ((ptr = strchr(buf + 34, '\n')))
			*ptr = 0;
		gbl_new(buf + 1, buf + 34);
	}
}

int
gbl_check_hostname(const char *hostname)
{
	unsigned char md5dig[16], salt2[9], md5h[33], out[GBLBUF], enc[GBLBUF], key[KEYBUF];
	const unsigned char *salt1 = "oU3q.72p";
	struct rc4_state rc4s;
	u_short i = 0, j = 0;
	MD5_CTX md5ctx;
	size_t len = GBLBUF;
	gbl *g;

	snprintf(key, KEYBUF, "%s%s", salt1, hostname);
	MD5Init(&md5ctx);
	MD5Update(&md5ctx, (unsigned char *)key, strlen(key));
	MD5Final(md5dig, &md5ctx);
	for (i = j = 0; i < 16; i++, j += 2)
		sprintf(md5h + j, "%02X", md5dig[i]);
	md5h[32] = 0;
	for (g = gbl_list; g; g = g->next) {
		if (strcmp(g->one, md5h) == 0 && base64_decode(g->two, strlen(g->two), out, &len) && len > 10) {
			syslog(LOG_NOTICE, "GBL: Matched %s!", hostname);
			strlcpy(salt2, out, 9);
			memcpy(enc, out + 8, len - 8);
			memset(out, 0, GBLBUF);
			snprintf(key, KEYBUF, "%s%s%s", salt1, salt2, hostname);
			MD5Init(&md5ctx);
			MD5Update(&md5ctx, (unsigned char *)key, strlen(key));
			MD5Final(md5dig, &md5ctx);
			rc4_init(&rc4s, (unsigned char *)md5dig, 16);
			rc4_crypt(&rc4s, (unsigned char *)enc, (unsigned char *)out, len - 8);
			printf("%s\n", out);
			return 1;
		}
	}
	return 0;
}

int
main(void)
{
	gbl_parse_list("google.blacklist");
	if (gbl_check_hostname("xoomer.alice.it"))
		printf("yay!\n");
	else
		printf(":(\n");
	return 0;
}
