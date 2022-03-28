# rd - privilege elevator
# Copyright (C) 2022 ArcNyxx
# see LICENCE file for licensing information

VERSION = 2.0.0

PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

GROUP = wheel # change to 'users' to permit any user to run

WPROFILE = -Wall -Wextra -Wstrict-prototypes -Wmissing-declarations \
-Wswitch-default -Wunreachable-code -Wcast-align -Wpointer-arith \
-Wbad-function-cast -Winline -Wundef -Wnested-externs -Wcast-qual -Wshadow \
-Wwrite-strings -Wno-unused-parameter -Wfloat-equal -Wpedantic
STD = -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
LIB = -lcrypt # removable if -DNO_PASSWD set

CFLAGS = $(WPROFILE) $(STD) -Os # add -DNO_PASSWD to disable password auth
LDFLAGS = $(LIB)
