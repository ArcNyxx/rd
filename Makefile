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
	rm -f rd $(OBJ) rd-*.tar.gz

dist: clean
	mkdir -p rd-$(VERSION)
	cp -R README LICENCE Makefile config.mk rd.1 $(SRC) rd-$(VERSION)
	tar -cf rd-$(VERSION).tar rd-$(VERSION)
	gzip rd-$(VERSION).tar
	rm -rf rd-$(VERSION)

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f rd $(DESTDIR)$(PREFIX)/bin
	chown root:$(GROUP) $(DESTDIR)$(PREFIX)/bin/rd
	chmod 4754 $(DESTDIR)$(PREFIX)/bin/rd
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	sed 's/VERSION/$(VERSION)/g' < rd.1 | sed 's/GROUP/$(GROUP)/g' \
		> $(DESTDIR)$(MANPREFIX)/man1/rd.1
	chmod 644 $(DESTDIR)$(MANPREFIX)/man1/rd.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/rd
	rm -f $(DESTDIR)$(MANPREFIX)/man1/rd.1

options:
	@echo rd build options
	@echo "CFLAGS = $(CFLAGS)"
	@echo "LDFLAGS = $(LDFLAGS)"

.PHONY: all clean dist install uninstall options
