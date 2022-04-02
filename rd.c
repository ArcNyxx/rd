/* rd - privilege elevator
 * Copyright (C) 2022 ArcNyxx
 * see LICENCE file for licensing information */

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef NO_PASSWD
#include <crypt.h>
#include <shadow.h>
#include <termios.h>
#endif /* NO_PASSWD */

static void die(const char *fmt, ...);
#ifndef NO_PASSWD
static char *readpw(void);
#endif /* NO_PASSWD */

static void
die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	/* perror if last char not '\n' */
	if (fmt[strlen(fmt) - 1] != '\n')
		perror(NULL);
	exit(127);
}

#ifndef NO_PASSWD
static char *
readpw(void)
{
	/* termios to not echo typed chars (hide passwd) */
	struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
		die("rd: unable to get terminal attributes");
	term.c_lflag &= ~ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		die("rd: unable to set terminal attributes");
	write(STDERR_FILENO, "rd: enter passwd: ", 18);

	/* read loop with buffer reallocation for long passwds */
	size_t length = 0, ret;
	char *passwd = malloc(50);
	while ((ret = read(STDIN_FILENO, passwd + length, 50)) == 50)
		if ((passwd = realloc(passwd, (length += 50) + 50)) == NULL)
			die("\nrd: unable to allocate memory");
	if (ret == (size_t)-1)
		die("\nrd: unable to read from stdin");
	passwd[length + ret - 1] = '\0';

	term.c_lflag |= ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		die("\nrd: unable to set terminal attributes");
	write(STDERR_FILENO, "\n", 1);
	return passwd;
}
#endif /* NO_PASSWD */

int
main(int argc, char **argv)
{
	int state = 0, add = 0;
	const char *user = "root";
	if (argc > 1 && argv[1][0] == '-' && strchr(argv[1], 'c') != NULL)
		state = add = 1;
	if (argc > 2 && argv[1][0] == '-' && strchr(argv[1], 'u') != NULL)
		add = 2, user = argv[2];
	argv = &argv[add];

	if (argv[1] == NULL)
		die("rd: no program given\n");
	if (getuid() != 0 && geteuid() != 0)
		die("rd: insufficient privileges\n");

	struct passwd *pw;
	if ((pw = getpwnam(user)) == NULL)
		die("rd: unable to get passwd file entry");

#ifndef NO_PASSWD
	if (access("/etc/rd", F_OK) == 0)
		goto skip;

	/* get hashed passwd from /etc/passwd or /etc/shadow */
	if (!strcmp(pw->pw_passwd, "x")) {
		struct spwd *sp;
		if ((sp = getspnam(user)) == NULL)
			die("rd: unable to get shadow file entry");
		pw->pw_passwd = sp->sp_pwdp;
	}
	if (pw->pw_passwd[0] == '!' || pw->pw_passwd[0] == '*')
		die("rd: password is locked\n");
	if (pw->pw_passwd[0] != '\0')
		/* hash and compare the read passwd to the shadow entry */
		if (strcmp(pw->pw_passwd, crypt(readpw(), pw->pw_passwd)))
			die("rd: incorrect password\n");

skip:
#endif /* NO_PASSWD */

	if (initgroups(user, pw->pw_gid) == -1)
		die("rd: unable to set groups");
	if (setgid(pw->pw_gid) == -1)
		die("rd: unable to set group id");
	if (setuid(pw->pw_uid) == -1)
		die("rd: unable to set user id");

	if (state) {
		const char *term = getenv("TERM"), *path = getenv("PATH");
		clearenv();
		setenv("TERM", term, 1);
		setenv("PATH", path, 1);
	}

	setenv("HOME", pw->pw_dir, 1);
	setenv("SHELL", pw->pw_shell[0] != '\0' ? pw->pw_shell : "/bin/sh", 1);
	setenv("USER", pw->pw_name, 1);
	setenv("LOGNAME", pw->pw_name, 1);

	execvp(argv[1], &argv[1]);
	if (errno == ENOENT)
		die("rd: unable to run %s: no such command\n", argv[1]);
	die("rd: unable to run %s", argv[1]);
}
