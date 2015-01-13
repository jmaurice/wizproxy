CC	=gcc
CPPFLAGS=-I../include -I/usr/local/include
CFLAGS	=-pipe -ggdb -O3 -Wunused -Wall -Wmissing-declarations -DNODB
LIBS	=-L/usr/local/lib/mysql -lmysqlclient -L/usr/local/lib -ladns

SRCS  = \
	b64.c\
	md5.c\
	rc4.c\
	strl.c\
	http.c\
	sock.c\
	db.c\
	main.c

OBJS=${SRCS:.c=.o}

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<
all: $(OBJS)
	$(CC) $(CFLAGS) -o wizproxy $(OBJS) $(LIBS)
clean:
	rm -f wizproxy *.o *.core core
install:
	install -c -m 555 wizproxy /usr/local/sbin
restart:
	killall wizproxy ; make clean all install && wizproxy
