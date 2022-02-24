/* rd - privilege elevator
 * Copyright (C) 2022 ArcNyxx
 * see LICENCE file for licensing information */

#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdnoreturn.h>
#include <unistd.h>

#ifndef NO_PASSWD
#include <crypt.h>
#include <shadow.h>
#include <termios.h>
#endif /* NO_PASSWD */

noreturn static void die(const char *fmt, ...);
#ifndef NO_PASSWD
static char *readpw(void);
#endif /* NO_PASSWD */

noreturn static void
die(const char *fmt, ...)
{
	/* perror if last char not '\n' */
	if (fmt[strlen(fmt) - 1] == '\n') {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	} else {
		perror(fmt);
	}
	exit(127);
}

#ifndef NO_PASSWD
static char *
readpw(void)
{
	write(STDOUT_FILENO, "rd: enter passwd: ", 18);
	/* termios to not echo typed chars (hide passwd) */
	struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
		die("\nrd: unable to get terminal attributes");

	term.c_lflag &= ~ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		die("\nrd: unable to set terminal attributes");

	/* read loop with buffer reallocation for long passwds */
	size_t length = 0, ret;
	char *passwd = malloc(50);
	while ((ret = read(STDIN_FILENO, passwd + length, 50)) == 50)
		if ((passwd = realloc(passwd, (length += ret) + 50)) == NULL)
			die("\nrd: unable to allocate memory");
	if (ret == (size_t)-1)
		die("\nrd: unable to read from stdin");
	passwd[length + ret - 1] = '\0';

	term.c_lflag |= ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		die("\nrd: unable to set terminal attributes");
	write(STDOUT_FILENO, "\n", 1);
	return passwd;
}
#endif /* NO_PASSWD */

int
main(int argc, char **argv)
{
	static const char *user = "root";

	if (getuid() != 0 && geteuid() != 0)
		die("rd: insufficient privileges\n");

#if defined(STATE) || defined(USRMOD)
	char inc = 1;

#ifdef STATE
	bool state = false;
	if (argc > 1 && argv[1][0] == '-' && strchr(argv[1], 'c') != NULL) {
		state = true;
		inc = 2;
	}
#endif

#ifdef USRMOD
	if (argc > 2 && argv[1][0] == '-' && strchr(argv[1], 'u') != NULL) {
		user = argv[2];
		inc = 3;
	}
#endif

	argv = &argv[inc];
#endif

#if defined(USRMOD)
	if (argc == 1 || argv[0][0] != '-')
		goto skip;

#ifdef USRMOD
	if (strchr(argv[0], 'u') != NULL) {
		if (argc < 2)
			die("rd: -u option must be followed by user\n");
		user = argv[1];
		argv = &argv[1];
	}
#endif /* USRMOD */
skip:
	argv = &argv[1];

#else
	argv = &argv[1];
#endif /* USRMOD */

	struct passwd *pw;
	if ((pw = getpwnam(user)) == NULL)
		die("rd: unable to get passwd file entry");

#ifndef NO_PASSWD
#ifdef RT_PASSWD
	if (access("/etc/rd", F_OK) == 0)
		goto skip
#endif /* RT_PASSWD */

	/* get hashed passwd from /etc/passwd or /etc/shadow */
	if (pw->pw_passwd[0] == '!' || pw->pw_passwd[0] == '*') {
		die("rd: password is locked\n");
	} else if (!strcmp(pw->pw_passwd, "x")) {
		struct spwd *sp;
		if ((sp = getspnam(user)) == NULL)
			die("rd: unable to get shadow file entry");
		pw->pw_passwd = sp->sp_pwdp;
	}

	/* if passwd exists (no free login) */
	if (pw->pw_passwd[0] != '\0') {
		/* get the salt from the entry */
		const char *salt;
		if ((salt = strdup(pw->pw_passwd)) == NULL)
			die("rd: unable to allocate memory");
		char *ptr = strchr(salt + 1, '$');
		ptr = strchr(ptr + 1, '$');
		ptr[1] = '\0';

		/* hash and compare the read passwd to the shadow entry */
		if (strcmp(pw->pw_passwd, crypt(readpw(), salt)))
			die("rd: incorrect password\n");
	}

#ifdef RT_PASSWD
skip:
#endif /* RT_PASSWD */
#endif /* NO_PASSWD */

//	if (initgroups(user, pw->pw_gid) < 0)
//		die("rd: unable to set groups");
	if (setgid(pw->pw_gid) == -1)
		die("rd: unable to set group id");
	if (setuid(pw->pw_uid) == -1)
		die("rd: unable to set user id");

#ifdef STATE
	if (state) {
		char *term = getenv("TERM");
		clearenv();
		setenv("TERM", term, 1);
	}
#endif /* STATE */

	setenv("HOME", pw->pw_dir, 1);
	setenv("SHELL", pw->pw_shell[0] != '\0' ? pw->pw_shell : "/bin/sh", 1);
	setenv("USER", pw->pw_name, 1);
	setenv("LOGNAME", pw->pw_name, 1);
	setenv("PATH", "/usr/local/bin:/usr/bin:/usr/sbin", 1);

	execvp(argv[0], argv);
	die("rd: unable to run %s: %s\n", argv[1], strerror(errno));
}
