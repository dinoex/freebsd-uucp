/*
 * Copyright (c) 1985, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Adams.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1985, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)uucpd.c	8.1 (Berkeley) 6/4/93";
#endif
static const char rcsid[] =
  "$FreeBSD: src/libexec/uucpd/uucpd.c,v 1.23 2001/07/09 09:23:42 brian Exp $";
#endif /* not lint */

/*
 * 4.2BSD TCP/IP server for uucico
 * uucico's TCP channel causes this server to be run at the remote end.
 */

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#include "pathnames.h"

#ifdef USE_PAM
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#endif /* USE_PAM */

#ifdef USE_PAM
static int auth_pam __P((void));

static pam_handle_t *pamh = NULL;
static char **environ_pam;

#define PAM_END { \
	if ((e = pam_setcred(pamh, PAM_DELETE_CRED)) != PAM_SUCCESS) \
		syslog(LOG_ERR, "pam_setcred: %s", pam_strerror(pamh, e)); \
	if ((e = pam_close_session(pamh,0)) != PAM_SUCCESS) \
		syslog(LOG_ERR, "pam_close_session: %s", pam_strerror(pamh, e)); \
	if ((e = pam_end(pamh, e)) != PAM_SUCCESS) \
		syslog(LOG_ERR, "pam_end: %s", pam_strerror(pamh, e)); \
}

struct cred_t {
	const char *uname;		/* user name */
	const char *pass;		/* password */
};
typedef struct cred_t cred_t;

#define COPY_STRING(s) (s ? strdup(s) : NULL)

#endif /* USE_PAM */

#if (MAXLOGNAME-1) > UT_NAMESIZE
#define LOGNAMESIZE UT_NAMESIZE
#else
#define LOGNAMESIZE (MAXLOGNAME-1)
#endif

#define	SCPYN(a, b)	strncpy(a, b, sizeof (a))

struct sockaddr_storage hisctladdr;
int hisaddrlen = sizeof hisctladdr;
struct sockaddr_storage myctladdr;
int mypid;

char Username[64], Logname[64];
char *nenv[] = {
	Username,
	Logname,
	NULL,
};

char user[64];
char passwd[64];

extern char **environ;
extern void logwtmp(char *line, char *name, char *host);

struct passwd *pw;
char remotehost[MAXHOSTNAMELEN];

void doit(struct sockaddr *sinp);
void dologout(void);
int readline(char start[], int num, int passw);
void dologin(struct passwd *pw, struct sockaddr *sin);

int main(int argc, char **argv)
{
	struct sockaddr *sin;

	environ = nenv;
	close(1); close(2);
	dup(0); dup(0);
	hisaddrlen = sizeof (hisctladdr);
	openlog("uucpd", LOG_PID, LOG_DAEMON);

	sin = (struct sockaddr *)&hisctladdr;
	if (getpeername(0, sin, &hisaddrlen) < 0) {
		syslog(LOG_ERR, "getpeername: %m");
		_exit(1);
	}

	realhostname_sa(remotehost, sizeof(remotehost) - 1, sin, sin->sa_len);
	remotehost[sizeof(remotehost) - 1] = '\0';

	doit(sin);
	exit(0);
}

void badlogin(char *name)
{

	syslog(LOG_NOTICE, "LOGIN FAILURE FROM %s", remotehost);
	syslog(LOG_AUTHPRIV|LOG_NOTICE,
	    "LOGIN FAILURE FROM %s, %s", remotehost, name);

	fprintf(stderr, "Login incorrect.\n");
	exit(1);
}

void doit(struct sockaddr *sinp)
{
	pid_t s;
	int pwdok = 0;
	int rval = -1; /* Assume PAM failed */
	int e; /* PAM rc */

	alarm(60);
	do {
		printf("login: "); fflush(stdout);
		errno = 0;
		if (readline(user, sizeof user, 0) < 0) {
			syslog(LOG_WARNING, "login read: %m");
			_exit(1);
		}
	} while (user[0] == '\0');

	/* truncate username to LOGNAMESIZE characters */
	user[LOGNAMESIZE] = '\0';

	/* always ask for passwords to deter account guessing */
	printf("Password: "); fflush(stdout);
	errno = 0;
	if (readline(passwd, sizeof passwd, 1) < 0) {
		syslog(LOG_WARNING, "passwd for '%s' read: %m", user);
		_exit(1);
	}
	alarm(0);

	/* pw might get changed by auth_pam */
	pw = getpwnam(user);

#ifdef USE_PAM
	/*
	 * Try to authenticate using PAM.  If a PAM system error
	 * occurs, perhaps because of a botched configuration,
	 * then fall back to using traditional Unix authentication.
	 */
	(void)setpriority(PRIO_PROCESS, 0, -4);
	rval = auth_pam();
	(void)setpriority(PRIO_PROCESS, 0, 0);

#endif /* USE_PAM */

	/*
	 * Fail after password if:
	 * 1. Invalid user
	 * 2. Shell is not uucico
	 * 3. Account has expired
	 * 4. Password is incorrect
	 */

	if (pw != NULL) {
		if (rval == -1) /* PAM bailed out */
			pwdok = (strcmp(crypt(passwd, pw->pw_passwd), pw->pw_passwd) == 0);
		else
			pwdok = (rval == 0);

		pwdok = pwdok && (*pw->pw_passwd != '\0')
			&& (strcmp(pw->pw_shell, _PATH_UUCICO) == 0)
			&& (!(pw->pw_expire && (time(NULL) >= pw->pw_expire)));
	}

	if (!pwdok)
		badlogin(user);

	sprintf(Username, "USER=%s", pw->pw_name);
	sprintf(Logname, "LOGNAME=%s", pw->pw_name);
	if ((s = fork()) < 0) {
		syslog(LOG_ERR, "fork: %m");
#ifdef USE_PAM
		PAM_END;
#endif
		_exit(1);
	} else if (s == 0) {
		dologin(pw, sinp);
		setgid(pw->pw_gid);
		initgroups(pw->pw_name, pw->pw_gid);
		chdir(pw->pw_dir);
		setuid(pw->pw_uid);

#ifdef USE_PAM
		if (pamh) {
			if ((e = pam_setcred(pamh, PAM_ESTABLISH_CRED))
			    != PAM_SUCCESS) {
				syslog(LOG_ERR, "pam_setcred: %s",
				       pam_strerror(pamh, e));
			} else if ((e = pam_open_session(pamh, 0)) != PAM_SUCCESS) {
				syslog(LOG_ERR, "pam_open_session: %s",
				       pam_strerror(pamh, e));
			}
			/* Tell PAM that our parent cares for us */
			if ((e = pam_end(pamh, PAM_DATA_SILENT)) != PAM_SUCCESS)
				syslog(LOG_ERR, "pam_end: %s",
				       pam_strerror(pamh, e));
		}
#endif /* USE_PAM_ */

		execl(pw->pw_shell, "uucico", (char *)NULL);
		syslog(LOG_ERR, "execl: %m");
		_exit(1);
	} else {
		/* parent - wait for child to finish, then cleanup
		   wtmp & session */
		/* Someone might decide to inline dologout() one day... */
		dologout();
#ifdef USE_PAM
		PAM_END;
#endif
	}
}


#ifdef USE_PAM
/*
 * PAM conv stolen from ftpd.c. We already got the password ourselves,
 * as most people wouldn't expect the UUCP login prompt to change.
 */

static int
auth_conv(int num_msg, const struct pam_message **msg,
	  struct pam_response **resp, void *appdata)
{
	int i;
	cred_t *cred = (cred_t *) appdata;
	struct pam_response *reply =
			malloc(sizeof(struct pam_response) * num_msg);

	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_ON:	/* assume want user name */
			reply[i].resp_retcode = PAM_SUCCESS;
			reply[i].resp = COPY_STRING(cred->uname);
			/* PAM frees resp. */
			break;
		case PAM_PROMPT_ECHO_OFF:	/* assume want password */
			reply[i].resp_retcode = PAM_SUCCESS;
			reply[i].resp = COPY_STRING(cred->pass);
			/* PAM frees resp. */
			break;
		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
			reply[i].resp_retcode = PAM_SUCCESS;
			reply[i].resp = NULL;
			break;
		default:			/* unknown message style */
			free(reply);
			return PAM_CONV_ERR;
		}
	}

	*resp = reply;
	return PAM_SUCCESS;
}

/*
 * Attempt to authenticate the user using PAM.  Returns 0 if the user is
 * authenticated, or 1 if not authenticated.  If some sort of PAM system
 * error occurs (e.g., the "/etc/pam.conf" file is missing) then this
 * function returns -1.  This can be used as an indication that we should
 * fall back to a different authentication mechanism.
 */
static int
auth_pam()
{
	const char *tmpl_user;
	const void *item;
	int rval;
	int e;

	cred_t auth_cred = { pw->pw_name, passwd };
	struct pam_conv conv = { &auth_conv, &auth_cred };

	if ((e = pam_start("uucp", user, &conv, &pamh)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_start: %s", pam_strerror(pamh, e));
		return -1;
	}

	if (remotehost != NULL &&
	    (e = pam_set_item(pamh, PAM_RHOST, remotehost)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_set_item(PAM_RHOST): %s",
		    pam_strerror(pamh, e));
		return -1;
	}
	e = pam_authenticate(pamh, 0);
	switch (e) {

	case PAM_SUCCESS:
		/*
		 * With PAM we support the concept of a "template"
		 * user.  The user enters a login name which is
		 * authenticated by PAM, usually via a remote service
		 * such as RADIUS or TACACS+.  If authentication
		 * succeeds, a different but related "template" name
		 * is used for setting the credentials, shell, and
		 * home directory.  The name the user enters need only
		 * exist on the remote authentication server, but the
		 * template name must be present in the local password
		 * database.
		 *
		 * This is supported by two various mechanisms in the
		 * individual modules.  However, from the application's
		 * point of view, the template user is always passed
		 * back as a changed value of the PAM_USER item.
		 */
		if ((e = pam_get_item(pamh, PAM_USER, &item)) ==
		    PAM_SUCCESS) {
			tmpl_user = (const char *) item;
			if (strcmp(user, tmpl_user) != 0)
				pw = getpwnam(tmpl_user);
		} else
			syslog(LOG_ERR, "Couldn't get PAM_USER: %s",
			    pam_strerror(pamh, e));
		rval = 0;
		break;

	case PAM_AUTH_ERR:
	case PAM_USER_UNKNOWN:
	case PAM_MAXTRIES:
		rval = 1;
		break;

	default:
		syslog(LOG_ERR, "pam_authenticate: %s", pam_strerror(pamh, e));
		rval = -1;
		break;
	}

	if (rval == 0) {
		e = pam_acct_mgmt(pamh, 0);
		if (e == PAM_NEW_AUTHTOK_REQD) {
			e = pam_chauthtok(pamh, PAM_CHANGE_EXPIRED_AUTHTOK);
			if (e != PAM_SUCCESS) {
				syslog(LOG_ERR, "pam_chauthtok: %s",
				    pam_strerror(pamh, e));
				rval = 1;
			}
		} else if (e != PAM_SUCCESS) {
			rval = 1;
		}
	}

	if (rval != 0) {
		if ((e = pam_end(pamh, e)) != PAM_SUCCESS) {
			syslog(LOG_ERR, "pam_end: %s", pam_strerror(pamh, e));
		}
		pamh = NULL;
	}
	return rval;
}
#endif /* USE_PAM */

int readline(char start[], int num, int passw)
{
	char c;
	register char *p = start;
	register int n = num;

	while (n-- > 0) {
		if (read(STDIN_FILENO, &c, 1) <= 0)
			return(-1);
		c &= 0177;
		if (c == '\n' || c == '\r' || c == '\0') {
			if (p == start && passw) {
				n++;
				continue;
			}
			*p = '\0';
			return(0);
		}
		if (c == 025) {
			n = num;
			p = start;
			continue;
		}
		*p++ = c;
	}
	return(-1);
}

void dologout(void)
{
	union wait status;
	pid_t pid;
	char line[32];

	while ((pid=wait((int *)&status)) > 0) {
		sprintf(line, "uucp%ld", (long)pid);
		logwtmp(line, "", "");
	}
}

/*
 * Record login in wtmp file.
 */
void dologin(struct passwd *pw, struct sockaddr *sin)
{
	char line[32];
	char remotehost[UT_HOSTSIZE + 1];
	int f;
	time_t cur_time;

	realhostname_sa(remotehost, sizeof(remotehost) - 1, sin, sin->sa_len);
	remotehost[sizeof remotehost - 1] = '\0';

	/* hack, but must be unique and no tty line */
	sprintf(line, "uucp%ld", (long)getpid());
	time(&cur_time);
	if ((f = open(_PATH_LASTLOG, O_RDWR)) >= 0) {
		struct lastlog ll;

		ll.ll_time = cur_time;
		lseek(f, (off_t)pw->pw_uid * sizeof(struct lastlog), L_SET);
		SCPYN(ll.ll_line, line);
		SCPYN(ll.ll_host, remotehost);
		(void) write(f, (char *) &ll, sizeof ll);
		(void) close(f);
	}
	logwtmp(line, pw->pw_name, remotehost);
}
