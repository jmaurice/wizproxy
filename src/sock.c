#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "proxy.h"
#include "sock.h"

int
sock_get_error(int sock)
{
	int errv, errlen = sizeof(errv);

	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &errv, &errlen) < 0) {
		syslog(LOG_ERR, "getsockopt(SO_ERROR) failed on socket(%d): %s", sock, strerror(errv));
		return -1;
	}

	return errv;
}

void
sock_read_error(proxy *p, int sock, struct in_addr ip, u_short port)
{
	int errv = sock_get_error(sock);

	if (debug >= 1)
		syslog(LOG_NOTICE, "Read error %d/%d from %s:%d with proxy state %lu on socket(%d): %s\n", errno, errv, inet_ntoa(ip), port, p->proxy_state, sock, strerror((errno > 0 ? errno : errv)));
	p->proxy_options |= PROXY_DEL;
}

void
sock_write_error(int sock)
{
	int errv = sock_get_error(sock);

	if (debug >= 1)
		syslog(LOG_NOTICE, "Write error %d/%d on socket(%d): %s\n", errno, errv, sock, strerror((errno > 0 ? errno : errv)));
}

int
sock_write(int sock, u_long *count, char *fmt, ...)
{
	char msgbuf[MAXBUF];
	va_list ap;
	int w = 0;

	va_start(ap, fmt);
	vsnprintf(msgbuf, MAXBUF, fmt, ap);
	if ((w = write(sock, msgbuf, strlen(msgbuf))) == -1) {
		sock_write_error(sock);
		return -1;
	} else if ((count) && w >= 0) {
		*count += w;
	}
	if (debug >= 2)
		printf(">3> %s", msgbuf);
	if (debug)
		printf("wrote(3) %d bytes, now count = %lu\n", w, *count);
	va_end(ap);
	return w;
}

int
sock_write_raw(int sock, u_long *count, void *data, size_t len)
{
	int w = 0;

	if ((w = write(sock, data, len)) == -1) {
		sock_write_error(sock);
		return -1;
	} else if ((count) && w >= 0) {
		*count += w;
	}
	if (debug >= 2)
		printf(">4> %s\n", (char *)data);
	if (debug)
		printf("wrote(4) %d bytes, now count = %lu\n", w, *count);
	return w;
}

int
sock_set_nonblock(int sock)
{
	struct linger linger_val = { 1, 1 };
	int flags;

	if ((flags = fcntl(sock, F_GETFL, 0)) == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;
	if (setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger_val, sizeof(linger_val)) == -1)
		return -1;

	return 0;
}

void
proxy_read(proxy *p)
{
	u_long w = 0;

	if (debug >= 2)
		printf(">1> %s\n", p->src_buf_ptr);

	if (sock_write_raw(p->dst_socket, &w, p->src_buf_ptr, p->src_buf_len) == -1) {
		p->proxy_options |= PROXY_DEL;
		return;
	}
	p->dst_bytes += p->src_buf_len;
	if (debug)
		printf("wrote(1) (w = %lu) %d bytes, (%lu/%lu)\n", w, p->src_buf_len, p->dst_bytes, (p->http_header_length + p->http_post_length));

	if (w > 0 && w < p->src_buf_len) {
		p->src_buf_len -= w;
		p->src_buf_ptr += w;
		p->proxy_options |= (p->proxy_options|PROXY_READING);
	} else {
		memset(p->src_buf, 0, MAXBUF);
		p->src_buf_len = 0;
		p->src_buf_ptr = p->src_buf;
		p->proxy_options &= ~PROXY_READING;
	}

	/* this is needed for <form enctype="multipart/form-data"> */
	/* if client is POST'ing and has reached bytes in Content-Length: header, finish with a \r\n at the end */
	if (p->http_post_length && p->dst_bytes >= (p->http_header_length + p->http_post_length)) {
		if (debug)
			printf("FINISH!\n");
		sock_write(p->dst_socket, &p->dst_bytes, "\r\n");
	}
}

void
proxy_write(proxy *p)
{
	u_long w = 0;

	if (debug >= 2)
		printf("<2< %s\n", p->dst_buf_ptr);

	if (sock_write_raw(p->src_socket, &w, p->dst_buf_ptr, p->dst_buf_len) == -1) {
		p->proxy_options |= PROXY_DEL;
	} else if (w > 0 && w < p->dst_buf_len) {
		p->dst_buf_len -= w;
		p->dst_buf_ptr += w;
		p->proxy_options |= (p->proxy_options|PROXY_WRITING);
	} else {
		memset(p->dst_buf, 0, MAXBUF);
		p->dst_buf_len = 0;
		p->dst_buf_ptr = p->dst_buf;
		p->proxy_options &= ~PROXY_WRITING;
	}
	p->src_bytes += w;
	if (debug)
		printf("wrote(2) %lu bytes\n", w);
}
