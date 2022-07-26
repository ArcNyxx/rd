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
#define SWAP(num1, num2) num1 += num2, num2 = num1 - num2, num1 -= num2
#endif /* TERM */
#endif /* PASS */

static void die(const char *fmt, ...);
#ifdef PASS
static char *readpw(void);
#endif /* PASS */

#ifdef VARS
extern char **environ;
#endif /* VARS */

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
	char data[76], *ptr;
	ssize_t ret, len = 0, num;
	if ((fd = open("/proc/self/stat", O_RDONLY | O_NOFOLLOW)) == -1)
		die("enc: unable to open file: ");
	while ((ret = read(fd, data + len, 76 - len)) > 0 &&
			(len += ret) < 76);
	if (ret == -1)
		die("enc: unable to read file: ");
	close(fd);

	dev_t term;
	for (ptr = data + 2; *ptr != '('; ++ptr);
	for (ptr += 17; *ptr != ')'; --ptr);
	for (num = 0, ++ptr; num < 4; num += (*++ptr == ' '));
	if ((term = strtoul(++ptr, NULL, 10)) == 0)
		die("enc: unable to find controlling terminal\n");

	num = minor(term), len = 0;
	do (data + 9)[len++] = '0' + (num % 10);
	while ((num /= 10) > 0);
	for (ssize_t i = 0; i < len / 2; ++i)
		SWAP((data + 9)[i], (data + 9)[len - i - 1]);
	data[len + 9] = '\0';

	struct stat at;
	memcpy(data, "/dev/pts/", 9);
	if (stat(data, &at) != -1 && S_ISCHR(at.st_mode) && at.st_rdev == term
			&& (fd = open(data, O_RDWR | O_NOCTTY)) != -1)
		return fd;
	memcpy(data + 1, "/dev/tty", 9); /* rely on data[0] == '/' */
	if (stat(data, &at) != -1 && S_ISCHR(at.st_mode) && at.st_rdev == term
			&& (fd = open(data, O_RDWR | O_NOCTTY)) != -1)
		return fd;
	return -1;
}
#endif /* TERM */

static char *
readpw(void)
{
	int fdin = STDIN_FILENO, fdout = STDERR_FILENO;
#ifdef TERM
	if ((fdin = fdout = getctty()) == -1)
		die("rd: unable to find controlling terminal\n");
#endif /* TERM */

	struct termios term;
	if (tcgetattr(fdin, &term) == -1)
		die("rd: unable to get terminal attributes: ");
	term.c_lflag &= ~ECHO;
	if (tcsetattr(fdin, TCSAFLUSH, &term) == -1)
		die("rd: unable to set terminal attributes: ");
	write(fdout, "rd: enter passwd: ", 18);

	char *pass;
	ssize_t ret, len = 0;
	if ((pass = malloc(50)) == NULL)
		die("\nrd: unable to allocate memory: ");
	while ((ret = read(fdin, pass + len, 50)) == 50)
		if (pass[len + 49] == '\n')
			break; /* prevents empty read */
		else if ((pass = realloc(pass, (len += 50) + 50)) == NULL)
			die("\nrd: unable to allocate memory: ");
	if (ret == -1)
		die("\nrd: unable to read from stdin: ");
	pass[len + ret - 1] = '\0';

	term.c_lflag |= ECHO;
	if (tcsetattr(fdin, TCSAFLUSH, &term) == -1)
		die("\nrd: unable to set terminal attributes: ");
	write(fdout, "\n", 1);
	return pass;
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
	struct stat at;
	if (stat("/etc/rd", &at) == -1 || at.st_mtime + PTIME < time(NULL)) {
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
		setenv("TERM", term, 1); setenv("PATH", path, 1);
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
