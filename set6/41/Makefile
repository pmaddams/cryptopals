PROG=		41
SRCS=		main.c	\
		rsa.c

LDFLAGS+=	-lcrypto

${PROG}: ${SRCS}
	cc ${SRCS} ${LDFLAGS} -o ${PROG}

clean:
	rm -f ${PROG}
