CLIENT=	36-client
SERVER=	36-server

COMMON=	util.c

all:
	make client
	make server

client: ${CLIENT}.c
	cc ${CLIENT}.c ${COMMON} -o ${CLIENT}

server: ${SERVER}.c
	cc ${SERVER}.c ${COMMON} -o ${SERVER}

clean:
	rm -f ${CLIENT} ${SERVER}
