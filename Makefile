CC		= gcc
CXX		= g++
CXXLD		= g++

PREFFLAGS	= -O2
CXXFLAGS	= $(PREFFLAGS) -Wall -Wextra
LDFLAGS		= -lcrypto

ALL_PROGS	= linkcheck
COMMON_OBJS	= 
COMMON_HEADERS	= 
prefix		= /usr/local


all:	$(ALL_PROGS)

linkcheck:	linkcheck.o $(COMMON_OBJS)
	$(CXXLD) -o $@ $^ $(LDFLAGS)

install:	$(ALL_PROGS)
	cp $(ALL_PROGS) $(prefix)/bin

clean:
	rm -f *% *~ *.o core $(ALL_PROGS)
