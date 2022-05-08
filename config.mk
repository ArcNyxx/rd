# rd - privilege elevator
# Copyright (C) 2022 ArcNyxx
# see LICENCE file for licensing information

VERSION = 2.1.0

PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

GROUP = wheel # change to 'users' to permit any user to run

WPROFILE = -Wall -Wextra -Wstrict-prototypes -Wmissing-declarations \
-Wswitch-default -Wunreachable-code -Wcast-align -Wpointer-arith \
-Wbad-function-cast -Winline -Wundef -Wnested-externs -Wcast-qual -Wshadow \
-Wwrite-strings -Wno-unused-parameter -Wfloat-equal -Wpedantic
STD = -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
LIB = -lcrypt # removable if -DNO_PASSWD set

# -DNO_PASSWD  disable all password auth
# -DNO_ACCESS  disable password auth by creating /etc/rd
# -DNO_STATE   disable -c flag (environment clearing)
# -DNO_USER    disable -u flag (users other than root)
MAC = # -DNO_PASSWD -DNO_ACCESS -DNO_STATE -DNO_USER

CFLAGS = $(WPROFILE) $(STD) $(MAC) -Os
LDFLAGS = $(LIB)
