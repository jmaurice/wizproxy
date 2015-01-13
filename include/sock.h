int				sock_write		(int, u_long *, char *, ...);
int				sock_set_nonblock	(int);
int				sock_get_error		(int);
void				sock_read_error		(proxy *, int, struct in_addr, u_short);
void				sock_write_error	(int);
void				proxy_read		(proxy *);
void				proxy_write		(proxy *);
int				sock_write_raw		(int, u_long *, void *, size_t);
