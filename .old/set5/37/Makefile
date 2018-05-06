CLIENT=		37-client
SERVER=		37-server

COMMON=		util.c

LDFLAGS+=	-lcrypto

all:
	make client
	make server

client: ${CLIENT}.c
	cc ${LDFLAGS} ${CLIENT}.c ${COMMON} -o ${CLIENT}

server: ${SERVER}.c
	cc ${LDFLAGS} ${SERVER}.c ${COMMON} -o ${SERVER}

clean:
	rm -f ${CLIENT} ${SERVER}
