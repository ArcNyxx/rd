/* rd - privilege elevator
 * Copyright (C) 2022 FearlessDoggo21
 * see LICENCE file for licensing information */

#include <crypt.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

noreturn static void die(const char *fmt, ...);
static char *readpw(void);

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
	exit(1);
}

static char *
readpw(void)
{
	printf("rd: enter passwd: ");
	fflush(stdout);

	/* termios to not echo typed chars (hide passwd) */
	struct termios origin, changed;
	if (tcgetattr(STDIN_FILENO, &origin) == -1)
		die("\nrd: unable to get terminal attributes");
	memcpy(&changed, &origin, sizeof(struct termios));

	changed.c_lflag &= ~ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &changed) == -1)
		die("\nrd: unable to set terminal attributes");

	/* read loop with buffer reallocation for long passwds */
	size_t length = 0, ret;
	char *passwd = malloc(50), *update = passwd;
	while ((ret = read(STDIN_FILENO, update, 50)) == 50) {
		if ((passwd = realloc(passwd, (length += ret) + 50)) == NULL)
			die("\nrd: unable to allocate memory");
		update = passwd + length;
	}
	if (ret == (size_t)-1)
		die("\nrd: unable to read from stdin");
	passwd[length + ret - 1] = '\0';

	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &origin) == -1)
		die("\nrd: unable to set terminal attributes");
	printf("\n");
	return passwd;
}

int
main(int argc, char **argv)
{
	if (getuid() != 0 && geteuid() != 0)
		die("rd: insufficient privileges\n");

	struct passwd *pw;
	if ((pw = getpwnam("root")) == NULL)
		die("rd: unable to get passwd file entry");

	if (pw->pw_passwd[0] == '!') {
		die("rd: password is locked\n");
	} else if (!strcmp(pw->pw_passwd, "x")) {
		struct spwd *sp;
		if ((sp = getspnam("root")) == NULL)
			die("rd: unable to get shadow file entry");

		/* get the salt from the entry */
		char *salt, *ptr;
		if ((salt = strdup(sp->sp_pwdp)) == NULL)
			die("rd: unable to allocate memory");
		ptr = strchr(salt + 1, '$');
		ptr = strchr(ptr + 1, '$');
		ptr[1] = '\0';

		/* hash and compare the read passwd to the shadow entry */
		const char *passwd = readpw();
		char *hash = crypt(passwd, salt);
		if (strcmp(hash, sp->sp_pwdp))
			die("rd: invalid password\n");
	}

	if (setgid(pw->pw_gid) == -1)
		die("rd: unable to set group id");
	if (setuid(pw->pw_uid) == -1)
		die("rd: unable to set user id");

	execvp(argv[1], &argv[1]);
	die("rd: unable to run %s: %s\n", argv[1], strerror(errno));
}
