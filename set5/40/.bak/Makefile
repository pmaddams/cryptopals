PROG=		40
SRCS=		main.c	\
		util.c

LDFLAGS+=	-lcrypto

${PROG}: ${SRCS}
	cc ${SRCS} ${LDFLAGS} -o ${PROG}

clean:
	rm -f ${PROG}
