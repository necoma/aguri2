PREFIX?=	/usr/local
INSTALL?=	/usr/bin/install
AGURIDIR?=	$(PREFIX)/lib/aguri

PROG=	aguri2
OBJS=	aguri.o aguri_ip.o aguri_pcap.o aguri_plot.o aguri_tree.o \
	read_pcap.o aguri_flow.o
SCRIPTS=	scripts/agurify.pl scripts/makeplot.pl \
	scripts/makeimages.pl scripts/density.pl

#CFLAGS=		-g -Wall
CFLAGS=		-O3 -Wall -DNDEBUG
DEFINES=	-DAGURI2 -DINET6 -DAGURI_STATS $(SYS_DEFINES)
INCLUDES=	-I. $(COMPAT_INCLUDES) $(SYS_INCLUDES)
LIBS=		$(SYS_LIBS) -lpcap

all: $(PROG)

install: $(PROG)
	$(INSTALL) -m 0755 $(PROG) $(PREFIX)/bin

aguri2: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(OBJS) $(LIBS)

.c.o: 
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $*.c

clean:;	-rm -f $(PROG) *.o core *.core *~
