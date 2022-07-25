# rd - privilege elevator
# Copyright (C) 2022 ArcNyxx
# see LICENCE file for licensing information

VERSION = 4.0.0

PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

GROUP = wheel # change to 'users' to permit any user to run

WPROFILE = -Wall -Wextra -Wstrict-prototypes -Wmissing-declarations \
-Wswitch-default -Wunreachable-code -Wcast-align -Wpointer-arith \
-Wbad-function-cast -Winline -Wundef -Wnested-externs -Wcast-qual -Wshadow \
-Wwrite-strings -Wno-unused-parameter -Wfloat-equal -Wpedantic
STD = -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
LIB = -lcrypt # with -DPASS

PTIME = 300 # seconds to allow passwd-less authorisation, with -DSAVE

# PASS - passwd authorisation
# SAVE - time-based passwd-less authorisation
# TERM - terminal device access
# VARS - -c flag for environment clearing
# USER - -u flag for alternative user login
MAC = -DPASS -DSAVE -DTERM -DVARS -DUSER -DPTIME=$(PTIME)

CFLAGS = $(WPROFILE) $(STD) $(MAC) -Os
LDFLAGS = $(LIB)
