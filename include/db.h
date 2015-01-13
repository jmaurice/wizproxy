void				proxy_log		(proxy *);
int				proxy_access_check	(proxy *);
int				http_access_check	(proxy *);
void				db_init			();
int				db_get_custinfo		(proxy *);

typedef struct dbinfo_t {
	char *		db_main_hostname;
	char *		db_main_username;
	char *		db_main_password;
	char *		db_main_database;
	char *		db_main_tbl_client;
	char *		db_main_tbl_site;
	char *		db_main_tbl_blklist;

	char *		db_cust_hostname;
	char *		db_cust_username;
	char *		db_cust_password;
	char *		db_cust_database;
	char *		db_cust_tbl_reseller;
	char *		db_cust_tbl_customer;

	char *		db_logs_hostname;
	char *		db_logs_username;
	char *		db_logs_password;
	char *		db_logs_database;
	char *		db_logs_tbl_log;

	char *		custimageurl;
} dbinfo;
