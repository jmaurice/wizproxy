#include <sys/types.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "proxy.h"
#include "http.h"
#include "sock.h"
#include "strl.h"
#include "db.h"

extern dbinfo dbi;

void
http_send_request(proxy *p)
{
	if (strcasecmp(p->http_method, "POST") == 0 && p->header_content_length)
		p->http_post_length = atoi(p->header_content_length);

	sock_write(p->dst_socket, &p->dst_bytes, "%s %s HTTP/1.0\r\n", p->http_method, p->http_path);

	if (p->header_host)
		sock_write(p->dst_socket, &p->dst_bytes, "Host: %s\r\n", p->header_host);
	if (p->header_cookie)
		sock_write(p->dst_socket, &p->dst_bytes, "Cookie: %s\r\n", p->header_cookie);
	if (p->header_referer)
		sock_write(p->dst_socket, &p->dst_bytes, "Referer: %s\r\n", p->header_referer);
	if (p->header_user_agent)
		sock_write(p->dst_socket, &p->dst_bytes, "User-Agent: %s\r\n", p->header_user_agent);
	if (p->header_content_type)
		sock_write(p->dst_socket, &p->dst_bytes, "Content-Type: %s\r\n", p->header_content_type);
	if (p->header_authorization)
		sock_write(p->dst_socket, &p->dst_bytes, "Authorization: %s\r\n", p->header_authorization);
	if (p->header_accept)
		sock_write(p->dst_socket, &p->dst_bytes, "Accept: %s\r\n", p->header_accept);
	if (p->header_accept_charset)
		sock_write(p->dst_socket, &p->dst_bytes, "Accept-Charset: %s\r\n", p->header_accept_charset);
	if (p->header_accept_encoding)
		sock_write(p->dst_socket, &p->dst_bytes, "Accept-Encoding: %s\r\n", p->header_accept_encoding);
	if (p->header_accept_language)
		sock_write(p->dst_socket, &p->dst_bytes, "Accept-Language: %s\r\n", p->header_accept_language);
	if (p->header_range)
		sock_write(p->dst_socket, &p->dst_bytes, "Range: %s\r\n", p->header_range);
	if (p->header_if_modified_since)
		sock_write(p->dst_socket, &p->dst_bytes, "If-Modified-Since: %s\r\n", p->header_if_modified_since);
	if (p->header_if_none_match)
		sock_write(p->dst_socket, &p->dst_bytes, "If-None-Match: %s\r\n", p->header_if_none_match);
	if (p->header_pragma)
		sock_write(p->dst_socket, &p->dst_bytes, "Pragma: %s\r\n", p->header_pragma);
	if (p->header_translate)
		sock_write(p->dst_socket, &p->dst_bytes, "Translate: %s\r\n", p->header_translate);
	if (p->header_overwrite)
		sock_write(p->dst_socket, &p->dst_bytes, "Overwrite: %s\r\n", p->header_overwrite);
	if (p->header_destination)
		sock_write(p->dst_socket, &p->dst_bytes, "Destination: %s\r\n", p->header_destination);
	if (p->header_depth)
		sock_write(p->dst_socket, &p->dst_bytes, "Depth: %s\r\n", p->header_depth);
	sock_write(p->dst_socket, &p->dst_bytes, "Connection: close\r\n");
/* content length must be last! */
	if (p->header_content_length)
		sock_write(p->dst_socket, &p->dst_bytes, "Content-Length: %s\r\n", p->header_content_length);

/* finish */
	sock_write(p->dst_socket, &p->dst_bytes, "\r\n");
	p->http_header_length = p->dst_bytes;

/* send extra stuff */
	if (p->header_extra_len > 0)
		sock_write_raw(p->dst_socket, &p->dst_bytes, p->header_extra, p->header_extra_len);
}

void
parse_header(proxy *p, char *str)
{
	char header[MAXBUF], value[MAXBUF];
	int i;

	for (i = 0; str[i] != 0 && str[i+1] != 0; i++)
		if (str[i] == ':') {
			str[i] = 0;
			strlcpy(header, str, MAXBUF);
			strlcpy(value, str+i+2, MAXBUF);
			// printf("found header: %s: %s\n", header, value);
			str[i] = ':';
			break;
		}
	if (strcasecmp(header, "host") == 0 && !p->header_host)
		p->header_host = lstrdup(value);
	else if (strcasecmp(header, "cookie") == 0 && !p->header_cookie)
		p->header_cookie = lstrdup(value);
	else if (strcasecmp(header, "referer") == 0 && !p->header_referer)
		p->header_referer = lstrdup(value);
	else if (strcasecmp(header, "user-agent") == 0 && !p->header_user_agent)
		p->header_user_agent = lstrdup(value);
	else if (strcasecmp(header, "content-type") == 0 && !p->header_content_type)
		p->header_content_type = lstrdup(value);
	else if (strcasecmp(header, "authorization") == 0 && !p->header_authorization)
		p->header_authorization = lstrdup(value);
	else if (strcasecmp(header, "accept") == 0 && !p->header_accept)
		p->header_accept = lstrdup(value);
	else if (strcasecmp(header, "accept-charset") == 0 && !p->header_accept_charset)
		p->header_accept_charset = lstrdup(value);
	else if (strcasecmp(header, "accept-encoding") == 0 && !p->header_accept_encoding)
		p->header_accept_encoding = lstrdup(value);
	else if (strcasecmp(header, "accept-language") == 0 && !p->header_accept_language)
		p->header_accept_language = lstrdup(value);
	else if (strcasecmp(header, "range") == 0 && !p->header_range)
		p->header_range = lstrdup(value);
	else if (strcasecmp(header, "transfer-encoding") == 0 && !p->header_transfer_encoding)
		p->header_transfer_encoding = lstrdup(value);
	else if (strcasecmp(header, "if-modified-since") == 0 && !p->header_if_modified_since)
		p->header_if_modified_since = lstrdup(value);
	else if (strcasecmp(header, "if-none-match") == 0 && !p->header_if_none_match)
		p->header_if_none_match = lstrdup(value);
	else if (strcasecmp(header, "proxy-connection") == 0 && !p->header_proxy_connection)
		p->header_proxy_connection = lstrdup(value);
	else if (strcasecmp(header, "connection") == 0 && !p->header_connection)
		p->header_connection = lstrdup(value);
	else if (strcasecmp(header, "pragma") == 0 && !p->header_pragma)
		p->header_pragma = lstrdup(value);
	else if (strcasecmp(header, "overwrite") == 0 && !p->header_overwrite)
		p->header_overwrite = lstrdup(value);
	else if (strcasecmp(header, "translate") == 0 && !p->header_translate)
		p->header_translate = lstrdup(value);
	else if (strcasecmp(header, "destination") == 0 && !p->header_destination)
		p->header_destination = lstrdup(value);
	else if (strcasecmp(header, "depth") == 0 && !p->header_depth)
		p->header_depth = lstrdup(value);
	else if (strcasecmp(header, "content-length") == 0 && !p->header_content_length)
		p->header_content_length = lstrdup(value);
	else if (debug)
		printf("HEADER IGNORED! %s: %s\n", header, value);
}

int
parse_request(proxy *p)
{
	char *buf, fdbuf[MAXBUF], mybuf[MAXBUF], buff[MAXBUF], *ar = NULL;
	int i, x = 0, z;

	if (p->http_request_len == 0)
		p->http_request = malloc(p->src_buf_len);
	else
		p->http_request = realloc(p->http_request, p->http_request_len + p->src_buf_len);

	memcpy(p->http_request + p->http_request_len, p->src_buf, p->src_buf_len);
	p->http_request_len += p->src_buf_len;

	memset(p->src_buf, 0, MAXBUF);
	p->src_buf_ptr = p->src_buf;
	p->src_buf_len = 0;

	if (!(ar = strstr(p->http_request, "\r\n\r\n")))
		return 0;

	ar[2] = 0;
	strlcpy(mybuf, p->http_request, MAXBUF);
	ar[2] = '\r';

	if ((p->http_request + p->http_request_len) > ar + 3) {
		ar += 4;
		p->header_extra_len = (p->http_request + p->http_request_len - ar);
		p->header_extra = malloc(p->header_extra_len);
		memcpy(p->header_extra, ar, p->header_extra_len);
		// printf("header extra len = %d, buf: %s\n", p->header_extra_len, p->header_extra);
	} else {
		ar = NULL;
	}

	if ((z = strlen(mybuf)) > MAXBUF - 10)
		return http_send_error(p, 400, 200, "BAD REQUEST", "Your headers were too long.");;

	for (i = 1; i < z; i++) {
		if (i + 1 < z && (mybuf[i] == '\r' && mybuf[i + 1] == '\n')) {
			p->parse_linenum++;
			mybuf[i] = 0;
			strlcpy(fdbuf, mybuf + x, MAXBUF);
			mybuf[i] = '\r';
			if (strlen(fdbuf) < 2)
				break;
			if (debug)
				printf("PARSE: %s\n", fdbuf);
			if (p->parse_linenum == 1) { /* parse request */
				if (!(buf = strtok(fdbuf, " ")))
					return http_send_error(p, 400, 200, "BAD REQUEST", "Your browser sent: %s", p->http_request);

			word:	p->parse_wordnum++;

				switch (p->parse_wordnum) {
					case 1: /* method */
						p->http_method = lstrdup(buf);
						break;
					case 2: /* url */
						p->http_url = lstrdup(buf);
						break;
					case 3: /* protocol version */
						p->http_version = lstrdup(buf);
						break;
				}

				if ((buf = strtok(NULL, " ")))
					goto word;

				p->parse_wordnum = 0;

			/* done parsing line, now parse request */

				if (p->http_method == NULL || p->http_url == NULL || p->http_version == NULL)
					return http_send_error(p, 400, 200, "BAD REQUEST", "Your browser sent: %s", p->http_request);

				if (strcmp(p->http_method, "CONNECT") == 0) {
					/* direct connections are very different from normal http requests */
					p->proxy_options |= PROXY_DIRECT;

					/* CONNECT www.paypal.com:443 HTTP/1.0 */
					/* we only need hostname and port */
					strlcpy(buff, p->http_url, MAXBUF);
					if ((buf = strtok(buff, ":")))
						p->http_hostname = lstrdup(buf);
					else
						p->http_hostname = lstrdup(buff);
					/* port */
					strlcpy(buff, p->http_url, MAXBUF);
					if (buff[0] == '/' || !(buf = strchr(buff, ':')) || buf + 1 == 0 || (p->http_port = atoi(buf + 1)) < 1)
						p->http_port = 80;

					/* done parsing, go. */
					p->proxy_state = STATE_GOTREQ;

#ifndef NODB
					/* check to see if hostname is blocked */
					if (http_access_check(p) != 0)
						return 1;
#endif

					/* now with clean buffer, connect out and be done */
					http_connect_out(p);
					return 0;
				}

				if (strncmp(p->http_url, "http://", 7) != 0 || strlen(p->http_url) < 10)
				{
					p->proxy_options |= PROXY_TRANS;
				} else {
				
					/* parse hostname */
					strlcpy(buff, p->http_url + 7, MAXBUF);
					if ((buf = strtok(buff, ":/$%^&?;")))
						p->http_hostname = lstrdup(buf);
					else
						p->http_hostname = lstrdup(p->http_url + 7);

					/* parse port, if none assume 80 */
					strlcpy(buff, p->http_url + 7 + strlen(p->http_hostname), MAXBUF);
					if (buff[0] == '/' || !(buf = strchr(buff, ':')) || buf + 1 == 0 || (p->http_port = atoi(buf + 1)) < 1)
						p->http_port = 80;

					/* now try to find path, if any */
					strlcpy(buff, p->http_url + 7 + strlen(p->http_hostname), MAXBUF);
					if (!(buf = strchr(buff, '/')) || buf + 1 == 0)
						p->http_path = lstrdup("/");
					else
						p->http_path = lstrdup(buff);
				}
			} else {
					parse_header(p, fdbuf);
			}
				x = i + 2;
			}
	}
	if(p->http_method != NULL && p->proxy_options & PROXY_TRANS)
	{
		if(p->header_host != NULL)
		{
			char buf2[MAXBUF], *bufx;
			strlcpy(buf2, p->header_host, MAXBUF);
			if (!(bufx = strtok(buf2, " ")))
				return http_send_error(p, 400, 200, "BAD REQUEST", "Empty Host: header");			
			
			if(!(bufx = strchr(buf2, ':')) || bufx + 1 == 0 || (p->http_port = atoi(bufx + 1)) < 1)
			{
				p->http_port = 80;
			} 
			p->http_hostname = lstrdup(buf2);
			p->http_path = lstrdup(p->http_url);
		} else 
			return http_send_error(p, 400, 200, "BAD REQUEST", "Missing Host: header");	
	}
	if (debug)
		printf("EOH! mybuf + x = %s\n", mybuf + x);
	if (p->http_method == NULL || p->http_hostname == NULL || p->http_url == NULL) /* eoh without request data? */
		return http_send_error(p, 400, 200, "BAD REQUEST", "Bad Request - Premature EOH");

	p->proxy_state = STATE_GOTREQ;

#ifndef NODB
/* check to see if hostname is blocked */
	if (http_eccess_check(p) != 0)
		return 1;
#endif

/* finally, connect to dst */
	http_connect_out(p);
	return 0;
}

int
parse_response(proxy *p)
{
	char fdbuf[MAXBUF], mybuf[MAXBUF], *ar = NULL;
	int i, z, x = 0;

	// must handle fragmented response
	if (p->http_response_len == 0)
		p->http_response = malloc(p->dst_buf_len);
	else
		p->http_response = realloc(p->http_response, p->http_response_len + p->dst_buf_len);
	memcpy(p->http_response + p->http_response_len, p->dst_buf, p->dst_buf_len);
	p->http_response_len += p->dst_buf_len;

	memset(p->dst_buf, 0, MAXBUF);
	p->dst_buf_ptr = p->dst_buf;
	p->dst_buf_len = 0;

	if (!(ar = strstr(p->http_response, "\r\n\r\n"))) {
		if (debug)
			printf("????????????????????????notyet EOH\n");
		return 0;
	}
	if (debug)
		printf("!!!!!!!!!!!!!!!! got response EOH\n");
	if (debug >= 2)
		printf("http response = %s", p->http_response);

	ar[2] = 0;
	strlcpy(mybuf, p->http_response, MAXBUF);
	ar[2] = '\r';

	if ((p->http_response + p->http_response_len) > ar + 3) {
		ar += 4;
		p->response_extra_len = (p->http_response + p->http_response_len - ar);
		p->response_extra = malloc(p->response_extra_len);
		memcpy(p->response_extra, ar, p->response_extra_len);
		// printf("response extra len = %d, buf: %s\n", p->response_extra_len, p->response_extra);
	} else {
		ar = NULL;
	}

	if ((z = strlen(mybuf)) > MAXBUF - 10)
		return http_send_error(p, 400, 200, "BAD REQUEST", "Responding server's headers were too long.");

	for (i = 1; i < z; i++) {
		if (i + 1 < z && mybuf[i] == '\r' && mybuf[i + 1] == '\n') {
			mybuf[i] = 0;
			strlcpy(fdbuf, mybuf + x, MAXBUF);
			mybuf[i] = '\r';
			if (debug)
				printf("parsing this: %s\n", fdbuf);
			if (strcasecmp(fdbuf, "Connection: keep-alive") == 0)
				; // sock_write(p->src_socket, &p->src_bytes, "Connection: close\r\n");
			else if (strncasecmp(fdbuf, "HTTP/1.1", 8) == 0)
				sock_write(p->src_socket, &p->src_bytes, "HTTP/1.0%s\r\n", fdbuf + 8);
			else
				sock_write(p->src_socket, &p->src_bytes, "%s\r\n", fdbuf);
			x = i + 2;
		}
	}
        if (debug)
                printf("EOH! mybuf + x = %s\n", mybuf + x);
	if (debug)
		printf("response extra = %d bytes\n", p->response_extra_len);
	sock_write(p->src_socket, &p->src_bytes, "\r\n");
	if (p->response_extra_len > 0)
		sock_write_raw(p->src_socket, &p->src_bytes, p->response_extra, p->response_extra_len);
	p->proxy_state = STATE_GOTRESP;
	return 0;
}

int
http_send_error(proxy *p, int result, int numeric, char *errmsg, char *fmt, ...)
{
	char msgbuf[MAXBUF];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msgbuf, MAXBUF, fmt, ap);

	if (p->proxy_customer != 0)
		db_get_custinfo(p);
	sock_write(p->src_socket, &p->src_bytes, "HTTP/1.0 %d %s\r\n", numeric, errmsg);
	sock_write(p->src_socket, &p->src_bytes, "Content-type: text/html\r\n");
	sock_write(p->src_socket, &p->src_bytes, "Connection: close\r\n");
	sock_write(p->src_socket, &p->src_bytes, "\r\n");
	sock_write(p->src_socket, &p->src_bytes, "<html>\n<head>\n<title>ERROR: Site Unavailable</title>\n");
	sock_write(p->src_socket, &p->src_bytes, "<style type=\"text/css\"><!--body{font-family:verdana,sans-serif}pre{font-family:sans-serif}--></style>\n");
	sock_write(p->src_socket, &p->src_bytes, "</head>\n<body>\n");
	if (dbi.custimageurl != NULL)
		sock_write(p->src_socket, &p->src_bytes, "<img src=\"http://%s%s\">\n", dbi.custimageurl, inet_ntoa(p->src_remote_ip));
	sock_write(p->src_socket, &p->src_bytes, "<h2>Site Unavailable</h2>\n<hr noshade size=\"1px\">\n");
	if (p->proxy_options & PROXY_TRANS)
		sock_write(p->src_socket, &p->src_bytes, "<p>While trying to retrieve the URL:<a href=\"http://%s%s\">http://%s%s</a>\n", p->http_hostname, p->http_path, p->http_hostname, p->http_path);
	else if (p->http_url != NULL)
		sock_write(p->src_socket, &p->src_bytes, "<p>While trying to retrieve the URL:<a href=\"%s\">%s</a>\n", p->http_url, p->http_url);
	sock_write(p->src_socket, &p->src_bytes, "<p>The following error was encountered:\n<ul><li><strong>%s: %s</strong></li></ul>\n", errmsg, msgbuf);
	if (p->proxy_customer_email != NULL)
		sock_write(p->src_socket, &p->src_bytes, "<p>Your administrator is <a href=\"mailto:%s\">%s</a>.<br>\n", p->proxy_customer_email, p->proxy_customer_email);
	sock_write(p->src_socket, &p->src_bytes, "<hr noshade size=\"1px\">\n</body>\n</html>\n");

	p->proxy_result = result;
	p->proxy_options |= PROXY_DEL;
	va_end(ap);

	return 1;
}
