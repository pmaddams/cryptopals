CLIENT=	36-client
SERVER=	36-server

all:
	make client
	make server

client: ${CLIENT}.c
	cc ${CLIENT}.c -o ${CLIENT}

server: ${SERVER}.c
	cc ${SERVER}.c -o ${SERVER}

clean:
	rm -f ${CLIENT} ${SERVER}
