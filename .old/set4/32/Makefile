CLIENT=		32-client
SERVER=		32-server
FILENAME=	DATA
DESTDIR=	/var/www/cgi-bin

LDFLAGS+=	-lcrypto -lssl

all:
	make client
	make server

client: ${CLIENT}.c
	cc -lcrypto -lssl ${CLIENT}.c -o ${CLIENT}

server: ${SERVER}.c
	cc -static ${SERVER}.c -o ${SERVER}
	doas -u root install -o www -g www -m 500 ${SERVER} ${DESTDIR}
	doas -u root cp ${FILENAME} ${DESTDIR}
	doas -u root rcctl restart slowcgi
	doas -u root rcctl restart httpd

clean:
	rm -f ${CLIENT} ${SERVER}
