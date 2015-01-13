void				http_send_request	(proxy *);
int				http_send_error		(proxy *, int, int, char *, char *, ...);
void				parse_header		(proxy *, char *);
int				parse_request		(proxy *);
int				parse_response		(proxy *);
