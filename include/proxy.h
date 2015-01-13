#ifndef __PROXY_H__
#define __PROXY_H__
#include <sys/types.h>
#include <netinet/in.h>
#include <adns.h>
#include <stdio.h>

#define MAXBUF 65535

typedef struct proxy_t {

	/* list pointers */
	struct proxy_t *		prev;
	struct proxy_t *		next;

	/* connection flags */
	u_long				proxy_options;			/* bitmask options for this connection */
	u_long				proxy_state;			/* state of connection */
	u_short				proxy_reseller;			/* from mysql lookup on ip */
	u_short				proxy_customer;			/* from mysql lookup on ip */
	char *				proxy_customer_email;
	u_long				proxy_type;			/* from mysql lookup on ip */
	time_t				proxy_last;			/* timestamp of last read/write */
	u_short				proxy_result;			/* result numeric from server */
	adns_query			proxy_dns_query;
	adns_answer *			proxy_dns_answer;

	/* socket stuff */
	int				src_socket;
	FILE *				src_fd;
	u_long				src_bytes;			/* bandwidth counter */
	char				src_buf[MAXBUF];		/* read buffer */
	char *				src_buf_ptr;
	int				src_buf_len;			/* bytes remaining to be proxied */
	struct in_addr			src_remote_ip;
	u_short				src_remote_port;

	int				dst_socket;
	FILE *				dst_fd;				/* outgoing socket fd */
	u_long				dst_bytes;			/* bandwidth counter */
	char				dst_buf[MAXBUF];
	char *				dst_buf_ptr;
	int				dst_buf_len;			/* bytes remaining to be proxied */
	struct sockaddr_in 		dst_sockaddr;
	struct in_addr			dst_remote_ip;

	/* parser stuff */
	u_short				parse_linenum;			/* parser's current line number */
	u_short				parse_wordnum;			/* parser's current word of line number */

	/* HTTP stuff */
	char *				http_request;			/* original request, gets realloc()'d */
	size_t				http_request_len;		/* size of above */
	char *				http_response;			/* original response, gets realloc()'d */
	size_t				http_response_len;		/* size of above */
	char *				http_method;			/* GET POST HEAD PUT */
	char *				http_url;			/* original http request url */
	char *				http_path;			/* original http request path */
	char *				http_version;			/* HTTP/1.0 or HTTP/1.1 */
	char *				http_hostname;			/* requested hostname */
	u_short				http_port;			/* requested port */
	u_long				http_header_length;		/* total bytes of headers sent to dst */
	u_long				http_post_length;		/* from Content-Length:, if any */
	struct hostent *		http_hostent;			/* required to resolve above */

/* save headers from original client request */
	char *				header_host;
	char *				header_cookie;
	char *				header_referer;
	char *				header_user_agent;
	char *				header_content_type;
	char *				header_authorization;
	char *				header_accept;
	char *				header_accept_charset;
	char *				header_accept_encoding;
	char *				header_accept_language;
	char *				header_range;
	char *				header_transfer_encoding;
	char *				header_if_modified_since;
	char *				header_if_none_match;
	char *				header_content_length;
	char *				header_proxy_connection;
	char *				header_connection;
	char *				header_pragma;
	char *				header_overwrite;
	char *				header_destination;
	char *				header_translate;
	char *				header_depth;
	char *				header_extra;			/* anything after headers, ie. POST data */
	size_t				header_extra_len;
	char *				response_extra;			/* anything after response headers, ie. HTML start */
	size_t				response_extra_len;

} proxy;

#define	STATE_NEW			1000
#define	STATE_GOTREQ			2000
#define	STATE_TRYDNS			2300
#define	STATE_GOTDNS			2700
#define	STATE_TRYCONN			3000
#define	STATE_DSTCONN			4000
#define	STATE_GOTRESP			5000
#define	STATE_2WAY			10000

#define	PROXY_DEL			0x0001				/* set if requesting directory */
#define	PROXY_WRITING			0x0002				/* writing faster than socket can handle */
#define	PROXY_READING			0x0004				/* reading faster than socket can handle */
#define	PROXY_DIRECT			0x0008				/* http request was CONNECT */
#define PROXY_TRANS			0x0010				/* transparent proxy */

void					do_signal		(int);
int					main			(int, char **);
void					io_loop			();
proxy *					proxy_new		(int, FILE *, struct in_addr, u_short);
void					proxy_del		(proxy *);
int					http_connect_out	(proxy *);

extern u_short debug;

#endif
