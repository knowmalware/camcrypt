CC=gcc
SRCDIR=camellia-GPL-1.1.0

camellia.so: ${SRCDIR}/camellia.c ${SRCDIR}/camellia.h
	${CC} -o camellia.so -fPIC -shared ${SRCDIR}/camellia.c

clean:
	rm *.so *.pyc

