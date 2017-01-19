PROG=		24
SRCS=		main.c	\
		mt.c
LDFLAGS+=	-lcrypto

${PROG}: ${SRCS}
	cc ${LDFLAGS} ${SRCS} -o ${PROG}

clean:
	rm -f ${PROG}
