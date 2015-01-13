#include <sys/types.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <mysql/mysql.h>
#include "proxy.h"
#include "http.h"
#include "strl.h"
#include "db.h"

MYSQL db_main, db_logs, db_cust;
extern dbinfo dbi;

void
proxy_log(proxy *p)
{
	char buffer[MAXBUF];

	snprintf(buffer, MAXBUF, "INSERT INTO ProxyLog(%sTS, %sOrg, %sCust, %sHost, %sResult, %sSrcSent, %sDstSent) VALUE (NOW(), '%u', '%u', '%s', '%u', '%lu', '%lu')", dbi.db_logs_tbl_log, dbi.db_logs_tbl_log, dbi.db_logs_tbl_log, dbi.db_logs_tbl_log, dbi.db_logs_tbl_log, dbi.db_logs_tbl_log, dbi.db_logs_tbl_log, p->proxy_reseller, p->proxy_customer, p->http_hostname, p->proxy_result, p->src_bytes, p->dst_bytes);

	mysql_ping(&db_logs);
	if (mysql_query(&db_logs, buffer))
		syslog(LOG_NOTICE, "Unable to log connection: %s", mysql_error(&db_logs));
}

int
proxy_access_check(proxy *p)
{
	MYSQL_RES *result = NULL;
	MYSQL_ROW row;
	char buffer[MAXBUF];

	mysql_ping(&db_main);
	snprintf(buffer, MAXBUF, "SELECT ProxyOrg, ProxyCust, ProxyType FROM ProxyAccess WHERE ProxyIP = '%s'", inet_ntoa(p->src_remote_ip));

	if (mysql_query(&db_main, buffer))
		http_send_error(p, 500, 200, "Internal Error", "(1)Unable to query: %s", mysql_error(&db_main));
	else if (!(result = mysql_store_result(&db_main)))
		http_send_error(p, 500, 200, "Internal Error", "(1)Unable to use mysql result: %s", mysql_error(&db_main));
	else if (mysql_num_rows(result) == 0)
		http_send_error(p, 407, 403, "Access Denied", "(1)Your IP (%s) is not allowed to access this proxy.", inet_ntoa(p->src_remote_ip));
	else if (!(row = mysql_fetch_row(result)))
		http_send_error(p, 500, 200, "Internal Error", "(1)Unable to fetch mysql row: %s", mysql_error(&db_main));
	else if (
			!(p->proxy_reseller = (u_long)strtol(row[0], (char **)NULL, 10)) ||
			!(p->proxy_customer = (u_long)strtol(row[1], (char **)NULL, 10)) ||
			!(p->proxy_type = (u_long)strtol(row[2], (char **)NULL, 10))
		)
		http_send_error(p, 500, 200, "Internal Error", "(1)No data in customer record.");
	else if (p->proxy_type != 1)
		http_send_error(p, 407, 200, "Access Denied", "(1)Your IP (%s) is not properly configured. Please contact support.", inet_ntoa(p->src_remote_ip));
	else
		goto allowed;

	if (result)
		mysql_free_result(result);
	return 1;

allowed:
	if (result)
		mysql_free_result(result);
	return 0;
}

int
http_access_check(proxy *p)
{
	MYSQL_RES *result = NULL;
	MYSQL_ROW row = NULL;
	char buffer[MAXBUF];
	int action = -1;

	/* trim extra trailing dots from hostname http://myspace.com./ */
	while (strlen(p->http_hostname) > 1 && p->http_hostname[strlen(p->http_hostname) - 1] == '.')
		p->http_hostname[strlen(p->http_hostname) - 1] = 0;

	/* check if site matches a ruleset entry */
	snprintf(buffer, MAXBUF, "SELECT %sHost, %sAction FROM %s WHERE ((%sOrg = 0 OR %sOrg = '%u') AND (%sCust = 0 OR %sCust = '%u')) AND (%sHost = 'ALL' OR %sHost = SUBSTRING_INDEX('%s', '.', -2) OR %sHost = SUBSTRING_INDEX('%s', '.', -3)) ORDER BY %sAction", dbi.db_main_tbl_site, dbi.db_main_tbl_site, dbi.db_main_tbl_site, dbi.db_main_tbl_site, dbi.db_main_tbl_site, p->proxy_reseller, dbi.db_main_tbl_site, dbi.db_main_tbl_site, p->proxy_customer, dbi.db_main_tbl_site, dbi.db_main_tbl_site, p->http_hostname, dbi.db_main_tbl_site, p->http_hostname, dbi.db_main_tbl_site);

	mysql_ping(&db_main);
	if (mysql_query(&db_main, buffer))
		http_send_error(p, 500, 200, "Internal Error", "(2)Unable to query: %s", mysql_error(&db_main));
	else if (!(result = mysql_store_result(&db_main)))
		http_send_error(p, 500, 200, "Internal Error", "(2)Unable to use mysql result: %s", mysql_error(&db_main));
	else if (mysql_num_rows(result) == 0)
		goto test2;
	else if (!(row = mysql_fetch_row(result)))
		http_send_error(p, 500, 200, "Internal Error", "(2)Unable to fetch mysql row: %s", mysql_error(&db_main));
	else if (!(action = (u_long)strtol(row[1], (char **)NULL, 10)) || row[1] == NULL)
		http_send_error(p, 500, 200, "Internal Error", "(2)Unable to get query result: %s", mysql_error(&db_main));
	else switch (action) {
		case 200:
			goto allowed;
		case 403:
			p->proxy_result = 403;
			break;
		case 301:
			/* redirect, etc. */
			break;
	}
	http_send_error(p, 403, 200, "Site Blocked", "Requests to '%s' from your network are not allowed.", row[0]);

	if (result)
		mysql_free_result(result);
	return 1;

test2:
	if (result)
		mysql_free_result(result);

	snprintf(buffer, MAXBUF, "SELECT 1 FROM %s WHERE %sHost = SUBSTRING_INDEX('%s', '.', -2)", dbi.db_main_tbl_blklist, dbi.db_main_tbl_blklist, p->http_hostname);

	mysql_ping(&db_main);
	if (mysql_query(&db_main, buffer))
		http_send_error(p, 500, 200, "Internal Error", "(3)Unable to query: %s", mysql_error(&db_main));
	else if (!(result = mysql_store_result(&db_main)))
		http_send_error(p, 500, 200, "Internal Error", "(3)Unable to use mysql result: %s", mysql_error(&db_main));
	else if (mysql_num_rows(result) > 0)
		http_send_error(p, 403, 200, "Site Blocked", "(3)The site you attempted to reach (%s) matches an entry in the system-wide blacklist. Contact your network administrator to request that this website be whitelisted.", p->http_hostname);
	else
		goto allowed;

	if (result)
		mysql_free_result(result);
	return 1;

allowed:
	p->proxy_result = 200;
	if (result)
		mysql_free_result(result);
	return 0;
}

int
db_get_custinfo(proxy *p)
{
	MYSQL_RES *result = NULL;
	MYSQL_ROW row = NULL;
	char buffer[MAXBUF];

	snprintf(buffer, MAXBUF, "SELECT %sEmail FROM %s WHERE %sID = '%d'", dbi.db_cust_tbl_customer, dbi.db_cust_tbl_customer, dbi.db_cust_tbl_customer, p->proxy_customer);

	mysql_ping(&db_cust);
	if (mysql_query(&db_cust, buffer))
		goto end;
	else if (!(result = mysql_store_result(&db_cust)))
		goto end;
	else if (mysql_num_rows(result) == 0)
		goto end;
	else if (!(row = mysql_fetch_row(result)))
		goto end;
	else if (!row[0] || strlen(row[0]) < 1)
		goto end;
	else {
		p->proxy_customer_email = lstrdup(row[0]);
	}

end:
	if (result)
		mysql_free_result(result);
	return 0;
}

void
db_init()
{
	if (!mysql_init(&db_main) || !mysql_init(&db_cust) || !mysql_init(&db_logs))
		errx(1, "Unable to initialize mysql data structure: %s", mysql_error(&db_main));

	if (!mysql_real_connect(&db_main, dbi.db_main_hostname, dbi.db_main_username, dbi.db_main_password, dbi.db_main_database, 0, NULL, 0))
		errx(1, "Error from MySQL database %s on server %s: %s", dbi.db_main_database, dbi.db_main_hostname, mysql_error(&db_main));
	if (!mysql_real_connect(&db_cust, dbi.db_cust_hostname, dbi.db_cust_username, dbi.db_cust_password, dbi.db_cust_database, 0, NULL, 0))
		errx(1, "Error from MySQL database %s on server %s: %s", dbi.db_cust_database, dbi.db_cust_hostname, mysql_error(&db_cust));
	if (!mysql_real_connect(&db_logs, dbi.db_logs_hostname, dbi.db_logs_username, dbi.db_logs_password, dbi.db_logs_database, 0, NULL, 0))
		errx(1, "Error from MySQL database %s on server %s: %s", dbi.db_logs_database, dbi.db_logs_hostname, mysql_error(&db_logs));

}
