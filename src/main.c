#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <err.h>
#include <grp.h>
#include <adns.h>
#include "proxy.h"
#include "sock.h"
#include "http.h"
#include "strl.h"
#include "db.h"
#define MAXLINE 128
#define MAXLFLD 10

int lsock, child_id = 0, children = 1;
adns_state proxy_dns_state;
proxy *proxy_list = NULL;
u_short prox = 0, debug = 0;
struct timeval now;
dbinfo dbi;

proxy *
proxy_new(int sock, FILE *fd, struct in_addr ip, u_short port)
{
	proxy *p;

	if ((p = malloc(sizeof(proxy))) == NULL)
		return NULL;
	memset(p, 0, sizeof(proxy));

	if (proxy_list) {
		p->next = proxy_list;
		proxy_list->prev = p;
	}
	proxy_list = p;

	p->src_socket = sock;
	p->src_fd = fd;
	p->src_remote_ip.s_addr = ip.s_addr;
	p->src_remote_port = port;
	p->proxy_state = STATE_NEW;
	p->proxy_last = now.tv_sec;

	prox++;
	return p;
}

void
proxy_del(proxy *p)
{
	if (proxy_list == p)
		proxy_list = (p->next ? p->next : NULL);
	if (p->prev)
		p->prev->next = p->next;
	if (p->next)
		p->next->prev = p->prev;

	free(p->http_method);
	free(p->http_request);
	free(p->http_response);
	free(p->http_url);
	free(p->http_path);
	free(p->http_hostname);
	free(p->http_version);
	free(p->header_host);
	free(p->header_cookie);
	free(p->header_referer);
	free(p->header_user_agent);
	free(p->header_content_type);
	free(p->header_authorization);
	free(p->header_accept);
	free(p->header_accept_charset);
	free(p->header_accept_encoding);
	free(p->header_accept_language);
	free(p->header_range);
	free(p->header_transfer_encoding);
	free(p->header_if_modified_since);
	free(p->header_if_none_match);
	free(p->header_content_length);
	free(p->header_proxy_connection);
	free(p->header_connection);
	free(p->header_pragma);
	free(p->header_extra);
	free(p->response_extra);
	free(p->proxy_customer_email);

	prox--;
	free(p);
}

int
main(int argc, char **argv)
{
	struct linger linger_val = { 1, 1 };
	struct sockaddr_in sin;
	u_short lport = 0, dofork = 1;
	int i, ln, one = 1; /* leave this set to 1 dam it */
	char line[MAXLINE], *field[MAXLFLD];
	FILE *fd = NULL;

	// close(0);

/* ignore sigpipe */
	signal(SIGPIPE, SIG_IGN);

/* parse command line options */
	while ((i = getopt(argc, argv, "df:")) != -1) {
		switch (i) {
			case 'd':
				debug = 1;
				dofork = 0;
				break;
			case 'f':
				if (!(fd = fopen(optarg, "r")))
					err(1, "Unable to open configuration file %s", optarg);
				break;
		}
	}

/* open configuration file if not done already above */
	if (!fd)
		fd = fopen("wizproxy.conf", "r");
	if (!fd)
		fd = fopen("/usr/local/etc/wizproxy/wizproxy.conf", "r");
	if (!fd)
		errx(1, "Unable to open configuration file");

/* read each line of configuration file and parse it out */
	for (ln = 0; fgets(line, MAXLINE, fd); ln++) {
		if (strlen(line) < 2 || line[0] == '#' || !strtok(line, ":"))
			continue;
		for(i = 0; i < MAXLFLD && (field[i] = strtok(NULL, ":")); i++);
		if (i < 1)
			continue;
		field[i - 1][strlen(field[i - 1]) - 1] = 0;
		switch (line[0]) {
			case '#':
				// comment
				break;
			case 'P':
				if ((lport = (u_short)atoi(field[0])) == 0)
					errx(1, "Error parsing configuration on line %d: invalid port number", ln);
				break;
			case 'N':
				if ((children = atoi(field[0])) < 1 || children > 1000)
					errx(1, "Error parsing configuration on line %d: invalid number of child processes, must be 1-1000", ln);
				break;
			case 'I':
				dbi.custimageurl = lstrdup(field[0]);
				break;
			case 'M':
				if (i < 7)
					errx(1, "Error parsing configuration on line %d: not enough arguments, need 7 got %d", ln, i);
				dbi.db_main_hostname = lstrdup(field[0]);
				dbi.db_main_username = lstrdup(field[1]);
				dbi.db_main_password = lstrdup(field[2]);
				dbi.db_main_database = lstrdup(field[3]);
				dbi.db_main_tbl_client = lstrdup(field[4]);
				dbi.db_main_tbl_site = lstrdup(field[5]);
				dbi.db_main_tbl_blklist = lstrdup(field[6]);
				break;
			case 'U':
				if (i < 6)
					errx(1, "Error parsing configuration on line %d: not enough arguments, need 6 got %d", ln, i);
				dbi.db_cust_hostname = lstrdup(field[0]);
				dbi.db_cust_username = lstrdup(field[1]);
				dbi.db_cust_password = lstrdup(field[2]);
				dbi.db_cust_database = lstrdup(field[3]);
				dbi.db_cust_tbl_reseller = lstrdup(field[4]);
				dbi.db_cust_tbl_customer = lstrdup(field[5]);
				break;
			case 'L':
				if (i < 5)
					errx(1, "Error parsing configuration on line %d: not enough arguments, need 5 got %d", ln, i);
				dbi.db_logs_hostname = lstrdup(field[0]);
				dbi.db_logs_username = lstrdup(field[1]);
				dbi.db_logs_password = lstrdup(field[2]);
				dbi.db_logs_database = lstrdup(field[3]);
				dbi.db_logs_tbl_log = lstrdup(field[4]);
				break;
		}
	}

/* sanity check */
	if (lport == 0) {
		warnx("Missing P: line in your configuration, defaulting to port 8080.");
		lport = 8080;
	}

/* setup listening socket for client connections */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	// sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	sin.sin_port = htons(lport);

	if ((lsock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "Unable to allocate listening socket");
	if (sock_set_nonblock(lsock) == -1)
		err(1, "Unable to set socket nonblocking");
	if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)) == -1)
		err(1, "Unable to setsockopt() for REUSE");
	if (setsockopt(lsock, SOL_SOCKET, SO_LINGER, (void *)&linger_val, sizeof(linger_val)) == -1)
		err(1, "Unable to setsockopt() for LINGER");
	if (bind(lsock, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(1, "Unable to bind()");
	if (listen(lsock, 7) == -1)
		err(1, "Unable to listen()");
	printf("Accepting connections on port %d!\n", lport);
	syslog(LOG_NOTICE, "Accepting connections on port %d!\n", lport);

/* lower privs */
	initgroups("2", 2);
	setgid(2);
	setuid(2);

/* fork */
	if (dofork) {
		if (fork() != 0)
			return 0;
		// close(1);
		// close(2);
		for (i = 1; i < children; i++) {
			usleep(5000);
			if (fork() == 0) {
				child_id = i;
				goto child;
			}
		}
	}
	syslog(LOG_NOTICE, "Spawned %d children!", children);
child:

#ifndef NODB
/* initialize mysql */
	db_init();
#endif

/* initialize adns state */
	adns_init(&proxy_dns_state, adns_if_nosigpipe|adns_if_noautosys, NULL);

/* infinite loop */
	io_loop();

/* never reached, but needed for compilier */
	return 0;
}

int
http_connect_out(proxy *p)
{
	if (p->proxy_state == STATE_GOTREQ) {
		if ((p->dst_remote_ip.s_addr = inet_addr(p->http_hostname)) != INADDR_NONE) {
			p->proxy_state = STATE_GOTDNS;
		} else {
			adns_submit(proxy_dns_state, p->http_hostname, adns_r_a, 0, p, &p->proxy_dns_query);
			p->proxy_state = STATE_TRYDNS;
			return 0;
		}
	}

	memset(&p->dst_sockaddr, 0, sizeof(p->dst_sockaddr));
	p->dst_sockaddr.sin_family = AF_INET;
	p->dst_sockaddr.sin_addr.s_addr = p->dst_remote_ip.s_addr;
	p->dst_sockaddr.sin_port = htons(p->http_port);

	if ((p->dst_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return http_send_error(p, 500, 500, "INTERNAL_ERROR", "Unable to allocate listening socket");
	if (sock_set_nonblock(p->dst_socket) == -1)
		return http_send_error(p, 500, 500, "INTERNAL_ERROR", "Unable to set socket non-blocking");
	if (!(p->dst_fd = fdopen(p->dst_socket, "r")))
		return http_send_error(p, 500, 500, "INTERNAL_ERROR", "Unable to fdopen()");
	if (connect(p->dst_socket, (struct sockaddr *)&p->dst_sockaddr, sizeof(p->dst_sockaddr)) == -1 && errno != EINPROGRESS)
		return http_send_error(p, 500, 500, "INTERNAL_ERROR", "Unable to connect to %s:%d", p->http_hostname, p->http_port);

	p->proxy_state = STATE_TRYCONN;

	return 0;
}

void
io_loop()
{
	fd_set readfds, writefds, exceptfds;
	struct sockaddr_in sin;
	size_t ssin = sizeof(sin);
	u_short checkfds = 0;
	int nsock, errv, r, fdsetsize = FD_SETSIZE;
	struct timeval tv, dnst;
	struct stat sb;
	proxy *p, *t;
	FILE *fd;

loop:
	gettimeofday(&now, NULL);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	memset(&sin, 0, sizeof(sin));
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	FD_SET(lsock, &readfds);

	for (p = proxy_list; p;) {
		if (checkfds == 1) {
			syslog(LOG_NOTICE, "io_loop: checking fds");
			if (fstat(p->src_socket, &sb) == -1) {
				syslog(LOG_NOTICE, "io_loop: src socket %d being deleted for fstat returning -1", p->src_socket);
				goto delsock;
			}
			if (p->proxy_state >= STATE_TRYCONN && fstat(p->dst_socket, &sb) == -1) {
				syslog(LOG_NOTICE, "io_loop: dst socket %d being deleted for fstat returning -1", p->dst_socket);
				goto delsock;
			}
		}
		if (p->proxy_options & PROXY_DEL) {
	delsock:
			close(p->src_socket);
			if (p->proxy_state >= STATE_TRYCONN)
				close(p->dst_socket);
#ifndef NODB
			if (p->proxy_state >= STATE_GOTREQ)
				proxy_log(p);
#endif
			t = p->next;
			proxy_del(p);
			p = t;
			continue;
		}
	/* stale socket cleanup */
		if (now.tv_sec - p->proxy_last > (p->proxy_options & PROXY_DIRECT ? 1800 : 60))
			goto delsock;
	/* logic to determine what fds to select at what state of proxy */
		switch (p->proxy_state) {
			case STATE_NEW:
				if (p->src_fd == NULL) /* something bad happened */
					goto delsock;
				if (p->dst_buf_len == 0)
					FD_SET(p->src_socket, &readfds);
				break;
			case STATE_TRYCONN:
				if (p->dst_fd == NULL) /* something bad happened */
					goto delsock;
				FD_SET(p->dst_socket, &writefds);
				break;
			case STATE_DSTCONN:
			case STATE_GOTRESP:
			case STATE_2WAY:
				if (p->src_fd == NULL || p->dst_fd == NULL) /* something bad happened */
					goto delsock;
				if (debug)
					printf("dst len = %d, src len = %d\n", p->dst_buf_len, p->src_buf_len);
				if (p->dst_buf_len == 0 && p->src_buf_len == 0) {
					FD_SET(p->src_socket, &readfds);
					FD_SET(p->dst_socket, &readfds);
				} else if (p->dst_buf_len > 0) {
					FD_SET(p->src_socket, &writefds);
				} else if (p->src_buf_len > 0) {
					FD_SET(p->dst_socket, &writefds);
				}
				break;
		}
	/* always set fds in exceptfds */
		FD_SET(p->src_socket, &exceptfds);
		if (p->dst_fd)
			FD_SET(p->dst_socket, &exceptfds);
	/* done with loop */
		p = p->next;
	}

	if (checkfds == 1)
		checkfds = 0;

	adns_beforeselect(proxy_dns_state, &fdsetsize, &readfds, &writefds, &exceptfds, NULL, &dnst, &now);
	if ((r = select(FD_SETSIZE, &readfds, &writefds, &exceptfds, &tv)) == -1) {
		if (errno == EBADF) {
			checkfds = 1;
			goto loop;
		}
		if (errno != EINTR)
			syslog(LOG_ALERT, "io_loop: select() returned -1: %d %s", errno, strerror(errno));
	}
	adns_afterselect(proxy_dns_state, fdsetsize, &readfds, &writefds, &exceptfds, &now);
	/* accept any new connections */
	if (FD_ISSET(lsock, &readfds)) {
		for (; (nsock = accept(lsock, (struct sockaddr *)&sin, &ssin)) != -1; memset(&sin, 0, ssin)) {
			if (sock_set_nonblock(nsock) == -1) {
				syslog(LOG_ERR, "sock_set_nonblock: failed for new accepted connection: %s", strerror(errno));
				close(nsock);
				continue;
			}
			if (!(fd = fdopen(nsock, "r"))) {
				syslog(LOG_ERR, "fdopen: failed on new accepted connection: %s", strerror(errno));
				sock_write(nsock, NULL, "HTTP/1.0 500 Server Error\r\n");
				close(nsock);
				continue;
			}
			if ((t = proxy_new(nsock, fd, sin.sin_addr, ntohs(sin.sin_port))) == NULL) { /* out of memory! */
				syslog(LOG_EMERG, "proxy_new: OUT OF MEMORY!!!");
				sock_write(nsock, NULL, "HTTP/1.0 500 Server Too Busy\r\n");
				fclose(fd);
				close(nsock);
				continue;
			}
#ifndef NODB
#warning proxy access check is disabled - open proxy warning!
			if (proxy_access_check(t) != 0)
				t->proxy_options |= PROXY_DEL;
#endif
		}
		r--;
	}

	for (p = proxy_list; r > 0 && p; p = p->next) {
		if (p->proxy_options & PROXY_DEL) {
			continue;
		} else if (FD_ISSET(p->src_socket, &exceptfds)) {
			syslog(LOG_NOTICE, "src excepted, deleting");
			sock_read_error(p, p->src_socket, p->src_remote_ip, p->src_remote_port);
			p->proxy_options |= PROXY_DEL;
		} else if (p->dst_fd && FD_ISSET(p->dst_socket, &exceptfds)) {
			syslog(LOG_NOTICE, "dst excepted, deleting");
			/* syslog(sock_get_error()) should be called instead */
			sock_write_error(p->dst_socket);
			p->proxy_options |= PROXY_DEL;
		} else if (p->proxy_state == STATE_TRYDNS) {
			// syslog(LOG_NOTICE, "checking dns");
			if (adns_check(proxy_dns_state, &p->proxy_dns_query, &p->proxy_dns_answer, NULL) == EAGAIN)
				continue;
			p->proxy_state = STATE_GOTDNS;
			if (p->proxy_dns_answer->status == adns_s_ok) {
				p->dst_remote_ip = *p->proxy_dns_answer->rrs.inaddr;
				http_connect_out(p);
			} else {
				http_send_error(p, 404, 200, "DNS Error", "Unable to resolve hostname: %s", p->http_hostname);
			}
			free(p->proxy_dns_answer);
		} else if (FD_ISSET(p->src_socket, &readfds) && r--) {
			if (debug)
				printf("src is ready for read, buflen = %d\n", p->src_buf_len);
			if (p->src_buf_len != 0)
				continue;
			memset(&p->src_buf, 0, MAXBUF);
			p->src_buf_ptr = p->src_buf;
			switch ((p->src_buf_len = read(p->src_socket, p->src_buf, MAXBUF))) {
				case -1: /* error */
					sock_read_error(p, p->src_socket, p->src_remote_ip, p->src_remote_port);
					continue;
				case 0: /* EOF */
					p->proxy_options |= PROXY_DEL;
					continue;
			}
			if (debug)
				printf("read %d bytes from src\n", p->src_buf_len);
			p->proxy_last = now.tv_sec;
			if (p->proxy_state < STATE_GOTREQ)
				parse_request(p);
		} else if (p->dst_fd && FD_ISSET(p->dst_socket, &readfds) && r--) {
			if (debug)
				printf("dst is ready for read, buflen = %d\n", p->dst_buf_len);
			if (p->dst_buf_len != 0)
				continue;
			memset(&p->dst_buf, 0, MAXBUF);
			p->dst_buf_ptr = p->dst_buf;
			switch ((p->dst_buf_len = read(p->dst_socket, p->dst_buf, MAXBUF))) {
				case -1: /* error */
					sock_read_error(p, p->dst_socket, p->dst_remote_ip, p->http_port);
					continue;
				case 0: /* EOF */
					p->proxy_options |= PROXY_DEL;
					continue;
			}
			if (debug)
				printf("read %d bytes from dst\n", p->dst_buf_len);
			p->proxy_last = now.tv_sec;
		} else if (FD_ISSET(p->src_socket, &writefds) && r--) {
			if (debug)
				printf("src is ready for write\n");
			if (p->proxy_state < STATE_GOTRESP)
				parse_response(p);
			else
				proxy_write(p);
		} else if (p->dst_fd && FD_ISSET(p->dst_socket, &writefds) && r--) {
			if (debug)
				printf("dst is ready for write\n");
			if (p->proxy_state >= STATE_DSTCONN) { /* if already connected */
				proxy_read(p);
				continue;
			} /* else, if not yet connected, check for errors */
			if ((errv = sock_get_error(p->dst_socket)) != 0) {
				http_send_error(p, 500, 500, "Network Error", "Unable to connect to %s on port %d: %s", p->http_hostname, p->http_port, strerror(errv));
				continue;
			}
			/* no errors (supposedly), mark socket connected */
			p->proxy_state = STATE_DSTCONN;
			if (p->proxy_options & PROXY_DIRECT) {
				sock_write(p->src_socket, &p->src_bytes, "HTTP/1.0 200 Established\r\n\r\n");
				p->proxy_state = STATE_2WAY;
			} else {
				/* send request */
				http_send_request(p);
			}
		}
	}
	goto loop;
}
