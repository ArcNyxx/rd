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

#ifdef PASS
#include <crypt.h>
#include <shadow.h>
#include <termios.h>

#if defined(SAVE) || defined(TERM)
#include <fcntl.h>
#include <sys/stat.h>
#endif /* SAVE || TERM */

#ifdef SAVE
#include <time.h>
#endif /* SAVE */

#ifdef TERM
#include <limits.h>
#include <sys/sysmacros.h>
#endif /* TERM */
#endif /* PASS */

static void die(const char *fmt, ...);
#ifdef PASS
static char *readpw(void);
#endif /* PASS */

extern char **environ;

static void
die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		perror(NULL);
	exit(127);
}

#ifdef PASS
#ifdef TERM
static int
getctty(void)
{
	int fd;
	if ((fd = open("/proc/self/stat", O_RDONLY | O_NOFOLLOW)) == -1)
		die("rd: unable to open file: ");

#define _STRING(str) #str
#define STRING(str) _STRING(str)
#define LEN (sizeof(STRING(INT_MAX)) - 1) * 5 + 25

	char data[LEN];
	size_t ret, len = 0;
	while ((ret = read(fd, data + len, LEN - len)) > 0 &&
			(len += ret) < LEN);
	if ((ssize_t)ret == -1)
		die("rd: unable to read file: ");
	close(fd);

	char *ptr;
	for (ptr = data + 2; *ptr != '('; ++ptr);
	for (ptr += 17 < (len - (ptr - data)) ? 17 : (len - (ptr - data));
			*ptr != ')'; --ptr);
	++ptr;
	for (size_t space = 0; space < 4; space += (*++ptr == ' '));
	len = 0;

	dev_t term;
	if ((term = strtoul(++ptr, NULL, 10)) == 0)
		die("rd: process does not have controlling terminal\n");
	for (size_t check = minor(term) / 10; check > 0; check /= 10, ++len);

	size_t num = minor(term), tlen = len;
	do
		(data + 9)[tlen--] = '0' + (num % 10);
	while ((num /= 10) > 0);
	data[len + 10] = '\0';

	struct stat info;
	memcpy(data + 1, "/dev/tty", 8);
	if (stat(data + 1, &info) != -1 && S_ISCHR(info.st_mode) &&
			info.st_rdev == term &&
			(fd = open(data + 1, O_RDWR | O_NOCTTY)) != -1)
		return fd;
	memcpy(data, "/dev/pts/", 9);
	if (stat(data, &info) != -1 && S_ISCHR(info.st_mode) &&
			info.st_rdev == term &&
			(fd = open(data, O_RDWR | O_NOCTTY)) != -1)
		return fd;
	die("rd: unable to find controlling terminal\n");
	return -1;
}
#endif /* TERM */

static char *
readpw(void)
{
#ifdef TERM
	int fd = getctty();

#undef  STDIN_FILENO
#undef  STDERR_FILENO
#define STDIN_FILENO  fd
#define STDERR_FILENO fd
#endif /* TERM */

	struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
		die("rd: unable to get terminal attributes: ");
	term.c_lflag &= ~ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		die("rd: unable to set terminal attributes: ");
	write(STDERR_FILENO, "rd: enter passwd: ", 18);

	size_t length = 0, ret;
	char *passwd;
	if ((passwd = malloc(50)) == NULL)
		die("\nrd: unable to allocate memory: ");
	while ((ret = read(STDIN_FILENO, passwd + length, 50)) == 50)
		if (passwd[length + 49] == '\n')
			break; /* prevents empty read */
		else if ((passwd = realloc(passwd,
				(length += 50) + 50)) == NULL)
			die("\nrd: unable to allocate memory: ");
	if (ret == (size_t)-1)
		die("\nrd: unable to read from stdin: ");
	passwd[length + ret - 1] = '\0';

	term.c_lflag |= ECHO;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) == -1)
		die("\nrd: unable to set terminal attributes: ");
	write(STDERR_FILENO, "\n", 1);
	return passwd;
}
#endif /* PASS */

int
main(int argc, char **argv)
{
	if (getuid() != 0 && geteuid() != 0)
		die("rd: insufficient privileges\n");

	const char *user = "root";
#if defined(VARS) || defined (USER)
	int add = 0;
#ifdef VARS
	int state = 0;
	if (argc > 1 && argv[1][0] == '-' && strchr(argv[1], 'c') != NULL)
		state = add = 1;
#endif /* VARS */
#ifdef USER
	if (argc > 2 && argv[1][0] == '-' && strchr(argv[1], 'u') != NULL)
		add = 2, user = argv[2];
#endif /* USER */
	argv = &argv[add];
#endif /* VARS || USER */

	if (argv[1] == NULL)
		die("rd: no program given\n");

	struct passwd *pw;
	if ((pw = getpwnam(user)) == NULL)
		die("rd: unable to get passwd file entry: ");

#ifdef PASS
#ifdef SAVE
	struct stat info;
	if (stat("/etc/rd", &info) == -1 ||
			info.st_mtim.tv_sec + PTIME < time(NULL)) {
#endif /* SAVE */
		if (!strcmp(pw->pw_passwd, "x")) {
			struct spwd *sp;
			if ((sp = getspnam(user)) == NULL)
				die("rd: unable to get shadow file entry: ");
			pw->pw_passwd = sp->sp_pwdp;
		}
		if (pw->pw_passwd[0] == '!')
			die("rd: password is locked\n");
		if (pw->pw_passwd[0] != '\0') {
			char *hash;
			if ((hash = crypt(readpw(), pw->pw_passwd)) == NULL)
				die("rd: unable to hash input: ");
			if (strcmp(pw->pw_passwd, hash))
				die("rd: incorrect password\n");
		}
#ifdef SAVE
	}

	int file;
	if ((file = creat("/etc/rd", S_IWUSR)) != -1)
		write(file, "", 1), close(file); /* update file mod time */
#endif /* SAVE */
#endif /* PASS */

	if (initgroups(user, pw->pw_gid) == -1)
		die("rd: unable to set groups: ");
	if (setgid(pw->pw_gid) == -1)
		die("rd: unable to set group id: ");
	if (setuid(pw->pw_uid) == -1)
		die("rd: unable to set user id: ");

#ifdef VARS
	if (state) {
		const char *term = getenv("TERM"), *path = getenv("PATH");
		environ = NULL;
		setenv("TERM", term, 1);
		setenv("PATH", path, 1);
	}
#endif /* VARS */

	setenv("HOME", pw->pw_dir, 1);
	setenv("SHELL", pw->pw_shell[0] != '\0' ? pw->pw_shell : "/bin/sh", 1);
	setenv("USER", pw->pw_name, 1);
	setenv("LOGNAME", pw->pw_name, 1);

	execvp(argv[1], &argv[1]);
	if (errno == ENOENT)
		die("rd: unable to run %s: no such command\n", argv[1]);
	die("rd: unable to run %s\n", argv[1]);
}
