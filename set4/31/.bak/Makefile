CLIENT=31-client
SERVER=31-server
DESTDIR=/var/www/cgi-bin
FILENAME=TEST

all:
	make client
	make server

client: ${CLIENT}.c
	cc -lcrypto -lssl ${CLIENT}.c -o ${CLIENT}

server: ${SERVER}.c
	cc -static ${SERVER}.c -o ${SERVER}
	install -o www -g www -m 500 ${SERVER} ${DESTDIR}
	cp ${FILENAME} ${DESTDIR}
	rcctl restart slowcgi
	rcctl restart httpd

clean:
	rm -f ${CLIENT} ${SERVER}
