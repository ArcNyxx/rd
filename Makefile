# rd - privilege elevator
# Copyright (C) 2022 ArcNyxx
# see LICENCE file for licensing information

.POSIX:

include config.mk

SRC = rd.c
OBJ = $(SRC:.c=.o)

all: rd

$(OBJ): config.mk

.c.o:
	$(CC) $(CFLAGS) -c $<

rd: $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

clean:
	rm -f rd $(OBJ) rd-$(VERSION).tar.gz

dist: clean
	mkdir -p rd-$(VERSION)
	cp -R README LICENCE Makefile config.mk rd.1 $(SRC) rd-$(VERSION)
	tar -cf - rd-$(VERSION) | gzip -c > rd-$(VERSION).tar.gz
	rm -rf rd-$(VERSION)

install: all
	mkdir -p $(PREFIX)/bin $(MANPREFIX)/man1
	cp -f rd $(PREFIX)/bin
	chown root:$(GROUP) $(PREFIX)/bin/rd
	chmod 4754 $(PREFIX)/bin/rd
	sed 's/VERSION/$(VERSION)/g;s/GROUP/$(GROUP)/g' < rd.1 \
		> $(MANPREFIX)/man1/rd.1
	chmod 644 $(MANPREFIX)/man1/rd.1

uninstall:
	rm -f $(PREFIX)/bin/rd $(MANPREFIX)/man1/rd.1

.PHONY: all clean dist install uninstall
