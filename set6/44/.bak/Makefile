PROG=		44
SRCS=		main.c	\
		util.c

LDFLAGS+=	-lcrypto

${PROG}: ${SRCS}
	cc ${LDFLAGS} ${SRCS} -o ${PROG}

clean:
	rm -f ${PROG}
