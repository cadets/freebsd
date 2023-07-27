/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <dttransport.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced.h"
#include "dtraced_chld.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

static size_t dirlen;

static void
dtt_elf(struct dtraced_state *s, dtt_entry_t *e)
{
	static char template[MAXPATHLEN];
	static int fd = 0;
	static char *elf = NULL;
	static size_t len = 0;
	static size_t offs = 0;
	char donepath[MAXPATHLEN] = { 0 };

	if (fd == -1)
		return;

	/*
	 * At this point we have the /var/ddtrace/inbound
	 * open and created, so we can just create new files in
	 * it without too much worry of failure because
	 * directory does not exist.
	 */
	if (fd == 0) {
		LOCK(&s->inbounddir->dirmtx);
		sprintf(template, "%s.elf.XXXXXXXXXXXXXX",
		    s->inbounddir->dirpath);
		UNLOCK(&s->inbounddir->dirmtx);

		fd = mkstemp(template);
		if (fd == -1) {
			ERR("%d: %s(): failed to mkstemp(%s): %m", __LINE__,
			    __func__, template);
			return;
		}

		elf = malloc(e->u.elf.totallen);
		if (elf == NULL) {
			ERR("%d: %s(): Failed to malloc elf: %m", __LINE__,
			    __func__);
			abort();
		}

		memset(elf, 0, e->u.elf.totallen);
		len = e->u.elf.totallen;
	}

	assert(offs < len && "Assertion happens if file was not created");
	if (offs + e->u.elf.len > len) {
		ERR("%d: %s(): offs + elflen (%zu) > len (%zu)", __LINE__,
		    __func__, offs + e->u.elf.len, len);
		return;
	}

	assert(offs + e->u.elf.len <= len &&
	    "Assertion happens if ELF segment length is too long");
	memcpy(elf + offs, e->u.elf.data, e->u.elf.len);
	offs += e->u.elf.len;

	if (e->u.elf.hasmore == 0) {
		if (write(fd, elf, len) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			ERR("%d: %s(): failed to write data to %s: %m",
			    __LINE__, __func__, template);
		}

		strncpy(donepath, template, dirlen);
		strcpy(donepath + dirlen, template + dirlen + 1);

		if (rename(template, donepath)) {
			ERR("%d: %s(): failed to move %s to %s: %m", __LINE__,
			    __func__, template, donepath);
		}

		free(elf);
		close(fd);
		fd = 0;
		offs = 0;
		len = 0;

		LOCK(&s->inbounddir->dirmtx);
		sprintf(template, "%s.elf.XXXXXXXXXXXXXX",
		    s->inbounddir->dirpath);
		UNLOCK(&s->inbounddir->dirmtx);
	}
}

static void
dtt_kill(struct dtraced_state *s, dtt_entry_t *e)
{
	pidlist_t *kill_entry;

	kill_entry = malloc(sizeof(pidlist_t));
	if (kill_entry == NULL) {
		ERR("%d: %s(): failed to malloc kill_entry: %m", __LINE__,
		    __func__);
		abort();
	}

	kill_entry->pid = e->u.kill.pid;

	LOCK(&s->kill_listmtx);
	dt_list_append(&s->kill_list, kill_entry);
	SIGNAL(&s->killcv);
	UNLOCK(&s->kill_listmtx);
}

static void
dtt_cleanup(struct dtraced_state *s)
{
	pidlist_t *pe = NULL;

	LOCK(&s->pidlistmtx);
	while (pe = dt_list_next(&s->pidlist)) {
		dt_list_delete(&s->pidlist, pe);
		WARN("%d: %s(): SIGKILL %d", __LINE__, __func__, pe->pid);
		(void)kill(pe->pid, SIGKILL);
		free(pe);
	}
	UNLOCK(&s->pidlistmtx);

	/* Re-exec ourselves to ensure full cleanup. */
	WARN("%d: %s(): re-execing", __LINE__, __func__);
	execve(s->argv[0], (char *const *)s->argv, NULL);
}

static int
setup_connection(struct dtraced_state *s)
{
	dtd_initmsg_t initmsg;
	struct sockaddr_un addr;
	int sockfd;
	size_t l;

	memset(&initmsg, 0, sizeof(initmsg));

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		ERR("%d: %s(): Failed creating a socket: %m", __LINE__,
		    __func__);
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		ERR("%d: %s(): Failed setting addr.sun_path to /var/ddtrace/sub.sock",
		    __LINE__, __func__);
		close(sockfd);
		return (-1);
	}

	SEMWAIT(&s->socksema);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		ERR("%d: %s(): connect to /var/ddtrace/sub.sock failed: %m",
		    __LINE__, __func__);
		close(sockfd);
		return (-1);
	}

	if (recv(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %m");
		close(sockfd);
		return (-1);
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		ERR("%d: %s(): Expected dtraced kind, got %d", __LINE__,
		    __func__, initmsg.kind);
		close(sockfd);
		return (-1);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = DTD_SUB_ELFWRITE;
	snprintf(initmsg.ident, DTRACED_FDIDENTLEN, "dtraced-dttransport-%d", getpid());

	if (send(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		ERR("%d: %s(): Failed to write initmsg to sockfd: %m", __LINE__,
		    __func__);
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}

/*
 * Runs in its own thread. Reads ELF files from dttransport and puts them in
 * the inbound directory.
 */
void *
listen_dttransport(void *_s)
{
	struct dtraced_state *s = (struct dtraced_state *)_s;
	dtt_entry_t e;
	struct kevent ev = { 0 };
	struct timespec ts;
	int kq, rval;

	LOCK(&s->inbounddir->dirmtx);
	dirlen = strlen(s->inbounddir->dirpath);
	UNLOCK(&s->inbounddir->dirmtx);

	kq = kqueue();
	if (kq == -1) {
		ERR("%d: %s(): failed to create kqueue: %m");
		broadcast_shutdown(s);
		pthread_exit(NULL);
	}

	if (enable_fd(kq, s->dtt_fd, EVFILT_READ, NULL) < 0) {
		ERR("%d: %s(): failed to enable EVFILT_READ on dtt_fd: %m");
		broadcast_shutdown(s);
		pthread_exit(NULL);
	}

	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	for (;;) {
		rval = dtraced_event(s, kq, NULL, 0, &ev, 1, &ts);

		if (atomic_load(&s->shutdown))
			break;

		if (rval < 0) {
			ERR("%d: %s(): dtraced_event failed: %m");
			broadcast_shutdown(s);
			pthread_exit(NULL);
		}

		assert((int)ev.ident == s->dtt_fd);
		assert(ev.filter == EVFILT_READ);
		if (read(s->dtt_fd, &e, sizeof(e)) < 0) {
			ERR("%d: %s(): read on dtt_fd failed: %m");
			broadcast_shutdown(s);
			pthread_exit(NULL);
		}

		switch (e.event_kind) {
		case DTT_ELF:
			dtt_elf(s, &e);
			break;

		case DTT_KILL:
			dtt_kill(s, &e);
			break;

		case DTT_CLEANUP_DTRACED:
			dtt_cleanup(s);
			break;

		default:
			ERR("%d: %s(): got unknown event (%d) from dttransport",
			    __LINE__, __func__, e.event_kind);
			break;
		}
	}

	pthread_exit(s);
}

void *
write_dttransport(void *_s)
{
	__cleanup(closefd_generic) int sockfd = -1;
	struct dtraced_state *s = (struct dtraced_state *)_s;
	dtt_entry_t e;
	size_t lentoread, len, totallen;
	uint32_t identifier;
	dtraced_hdr_t header;
	ssize_t r;
	uintptr_t msg_ptr;
	unsigned char *msg;

	lentoread = len = totallen = 0;

	sockfd = setup_connection(s);
	if (sockfd == -1)
		pthread_exit(NULL);

	while (atomic_load(&s->shutdown) == 0) {
		if (recv(sockfd, &header, DTRACED_MSGHDRSIZE, 0) < 0) {
			ERR("%d: %s(): Failed to recv from sub.sock: %m",
			    __LINE__, __func__);
			continue;
		}

		if (DTRACED_MSG_TYPE(header) != DTRACED_MSG_ELF) {
			ERR("%d: %s(): Received unknown message type: %lu",
			    __LINE__, __func__, DTRACED_MSG_TYPE(header));
			broadcast_shutdown(s);
			pthread_exit(NULL);
		}

		len = DTRACED_MSG_LEN(header);
		msg = malloc(len);
		if (msg == NULL) {
			ERR("%d: %s(): Failed to allocate a new message: %m",
			    __LINE__, __func__);
			abort();
		}

		totallen = len;
		identifier = arc4random();
		msg_ptr = (uintptr_t)msg;
		for (;;) {
			r = recv(sockfd, (void *)msg_ptr, len, 0);
			if (r < 0) {
				ERR("%d: %s(): Exiting write_dttransport(): %m",
				    __LINE__, __func__);
				broadcast_shutdown(s);
				pthread_exit(NULL);
			} else if ((size_t)r == len)
				break;

			len -= r;
			msg_ptr += r;
		}


		msg_ptr = (uintptr_t)msg;
		len = totallen;

		while (len != 0) {
			memset(&e, 0, sizeof(e));
			lentoread = len > DTT_MAXDATALEN ? DTT_MAXDATALEN : len;

			e.event_kind = DTT_ELF;
			e.u.elf.identifier = identifier;
			e.u.elf.hasmore = len > DTT_MAXDATALEN ? 1 : 0;
			e.u.elf.len = lentoread;
			e.u.elf.totallen = totallen;
			memcpy(e.u.elf.data, msg, lentoread);

			if (unlikely(write(s->dtt_fd, &e, sizeof(e)) < 0)) {
				/*
				 * If we don't have dttransport opened,
				 * we just move on. It might get opened
				 * at some point.
				 */
				sleep(5);
				continue;
			}

			len -= lentoread;
			msg += lentoread;

			assert(len >= 0 && len < totallen);
			assert((uintptr_t)msg >= msg_ptr);
			assert((uintptr_t)msg <= (msg_ptr + totallen));
		}
		assert(len == 0);

		free((void *)msg_ptr);
	}

	pthread_exit(s);
}
