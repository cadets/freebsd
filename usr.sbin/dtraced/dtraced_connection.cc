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
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_id.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#define DTRACED_BACKLOG_SIZE 10000

int
send_ack(int fd)
{

	unsigned char ack = 1;
	return (send(fd, &ack, 1, 0) < 0);
}

int
send_nak(int fd)
{

	unsigned char ack = 0;
	return (send(fd, &ack, 1, 0) < 0);
}

int
enable_fd(int kq, int fd, int filt, void *data)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, filt, EV_ADD | EV_ENABLE, 0, 0, data);
	DEBUG("%d: %s(): Enable %d", __LINE__, __func__, fd);
	return (kevent(kq, change_event, 1, NULL, 0, NULL) < 0);
}

int
reenable_fd(int kq, int fd, int filt)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, filt, EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
	DEBUG("%d: %s(): Re-enable %d", __LINE__, __func__, fd);
	return (kevent(kq, change_event, 1, NULL, 0, NULL));
}

int
disable_fd(int kq, int fd, int filt)
{
	struct kevent change_event[1];

	EV_SET(change_event, fd, filt, EV_DISABLE | EV_KEEPUDATA, 0, 0, 0);
	DEBUG("%d: %s(): Disable %d", __LINE__, __func__, fd);
	return (kevent(kq, change_event, 1, NULL, 0, NULL));
}

void *
close_filedescs(void *_s)
{
	struct dtraced_state *s = (struct dtraced_state *)_s;
	int count;

	while (s->shutdown.load() == 0) {
		sleep(DTRACED_CLOSEFD_SLEEPTIME);
		LOCK(&s->deadfdsmtx);
		for (auto it = s->deadfds.begin(); it != s->deadfds.end();) {
			dtraced_fd_t *dfd = *it;
			/*
			 * If it's still referenced somewhere, we don't close
			 * it. We'll pick it up on the next run.
			 */
			count = dfd->__count.load();
			if (count != 0) {
				DEBUG("%d: %s(): fd %d (ident=%s, count=%d)\n",
				    __LINE__, __func__, dfd->fd, dfd->ident,
				    count);
				++it;
				continue;
			}

			if (dfd->cleaned_up == 0) {
				/*
				 * We haven't cleaned our jobs up yet. Delay the
				 * closing of this file descriptor until we do.
				 */
				++it;
				continue;
			}

			it = s->deadfds.erase(it);
			assert(dfd->__count.load() == 0);
			LOG("%d: %s(): close(%p, %d-%s)\n", __LINE__, __func__,
			    dfd, dfd->fd, dfd->ident);
			close(dfd->fd);
			free(dfd);
		}
		UNLOCK(&s->deadfdsmtx);
	}

	pthread_exit(_s);
}

static void
enqueue_info_message(struct dtraced_state *s, dtraced_fd_t *dfd)
{
	struct dtraced_job *job;

	job = dtraced_new_job(SEND_INFO, dfd);
	if (job == NULL)
		abort();

	LOCK(&s->joblistmtx);
	s->joblist.push_back(job);
	UNLOCK(&s->joblistmtx);
}

static int
accept_new_connection(struct dtraced_state *s)
{
	int connsockfd;
	int on = 1;
	dtraced_fd_t *dfd;
	dtd_initmsg_t initmsg;

	memset(&initmsg, 0, sizeof(initmsg));

	connsockfd = accept(s->sockfd, NULL, 0);
	if (connsockfd == -1) {
		ERR("%d: %s(): accept() failed: %m", __LINE__, __func__);
		return (-1);
	}

	if (setsockopt(connsockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on))) {
		close(connsockfd);
		ERR("%d: %s(): setsockopt() failed: %m", __LINE__, __func__);
		return (-1);
	}

	initmsg.kind = DTRACED_KIND_DTRACED;
	if (send(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		ERR("%d: %s(): send() initmsg to connsockfd failed: %m",
		    __LINE__, __func__);
		return (-1);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	if (recv(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		ERR("%d: %s(): recv() get initmsg failed: %m", __LINE__,
		    __func__);
		return (-1);
	}

	dfd = (dtraced_fd_t *)malloc(sizeof(dtraced_fd_t));
	if (dfd == NULL) {
		ERR("%d: %s(): malloc() failed with: %m", __LINE__, __func__);
		abort();
	}

	memset(dfd, 0, sizeof(dtraced_fd_t));
	dfd->fd = connsockfd;
	dfd->kind = initmsg.kind;
	dfd->subs = initmsg.subs;
	memcpy(dfd->ident, initmsg.ident, DTRACED_FDIDENTLEN);
	dtraced_tag_fd(dfd);

	if (enable_fd(s->kq_hdl, connsockfd, EVFILT_READ, dfd) < 0) {
		close(connsockfd);
		free(dfd);
		ERR("%d: %s(): kevent() adding new connection failed: %m",
		    __LINE__, __func__);
		return (-1);
	}

	if (enable_fd(s->kq_hdl, connsockfd, EVFILT_WRITE, dfd) < 0) {
		close(connsockfd);
		free(dfd);
		ERR("%d: %s(): kevent() adding new connection failed: %m",
		    __LINE__, __func__);
		return (-1);
	}

	LOG("%d: %s(): accept(%d, %x, 0x%x, %s)", __LINE__, __func__, dfd->fd,
	    dfd->kind, dfd->subs, dfd->ident);
	LOCK(&s->socklistmtx);
	s->sockfds.insert(dfd);
	UNLOCK(&s->socklistmtx);

	if (dfd->subs & DTD_SUB_INFO) {
		enqueue_info_message(s, dfd);
	}

	return (0);
}

static void
kill_socket(struct dtraced_state *s, dtraced_fd_t *dfd)
{
	/* Remove it from the socket list and shutdown */
	LOCK(&s->socklistmtx);
	s->sockfds.erase(dfd);
	UNLOCK(&s->socklistmtx);

	shutdown(dfd->fd, SHUT_RDWR);

	/*
	 * Add it to the deadfds list and let it get cleaned up by other
	 * threads.
	 */
	LOCK(&s->deadfdsmtx);
	s->deadfds.insert(dfd);
	SIGNAL(&s->jobcleancv);
	UNLOCK(&s->deadfdsmtx);
}

static int
disable_rw(int kq, int fd)
{

	return (disable_fd(kq, fd, EVFILT_READ) ||
	    disable_fd(kq, fd, EVFILT_WRITE));
}

void *
process_consumers(void *_s)
{
	int err;
	int new_events;
	__cleanup(closefd_generic) int kq = -1;
	dtraced_fd_t *dfd;
	int efd;
	int dispatch;
	int i;
	struct dtraced_state *s = (struct dtraced_state *)_s;
	struct timespec ts;

	struct kevent event[1] = { {} };

	/*
	 * Sanity checks on the state.
	 */
	if (s == NULL)
		pthread_exit(NULL);

	if (s->socktd == NULL)
		pthread_exit(NULL);

	if (s->sockfd == -1)
		pthread_exit(NULL);

	err = listen(s->sockfd, DTRACED_BACKLOG_SIZE);
	if (err != 0) {
		ERR("%d: %s(): Failed to listen on %d: %m", __LINE__, __func__,
		    s->sockfd);
		broadcast_shutdown(s);
		pthread_exit(NULL);
	}

	kq = kqueue();
	if (kq == -1) {
		ERR("%d: %s(): Failed to create dtraced socket kqueue: %m",
		    __LINE__, __func__);
		broadcast_shutdown(s);
		pthread_exit(NULL);
	}

	if (enable_fd(kq, s->sockfd, EVFILT_READ, NULL)) {
		ERR("%d: %s(): Failed to register listening socket kevent: %m",
		    __LINE__, __func__);
		close(kq);
		broadcast_shutdown(s);
		pthread_exit(NULL);
	}

	s->kq_hdl = kq;
	SEMPOST(&s->socksema);

	ts.tv_sec = DTRACED_EVENTSLEEPTIME;
	ts.tv_nsec = 0;
	for (;;) {
		new_events = dtraced_event(s, kq, NULL, 0, event, 1, &ts);

		if (s->shutdown.load())
			break;

		if (new_events == -1) {
			ERR("%d: %s(): dtraced_event failed: %m");
			broadcast_shutdown(s);
			pthread_exit(NULL);
		}

		for (i = 0; i < new_events; i++) {
			dfd = (dtraced_fd_t *)event[i].udata;
			efd = event[i].ident;

			if (efd == s->sockfd && event[i].flags & EV_ERROR) {
				ERR("%d: %s(): error on %s: %m", __LINE__,
				    __func__, DTRACED_SOCKPATH);
				broadcast_shutdown(s);
				pthread_exit(NULL);
			}

			if (efd == s->sockfd && event[i].flags & EV_EOF) {
				ERR("%d: %s(): EOF on %s: %m", __LINE__,
				    __func__, DTRACED_SOCKPATH);
				broadcast_shutdown(s);
				pthread_exit(NULL);
			}

			if (event[i].flags & EV_ERROR ||
			    event[i].flags & EV_EOF) {
				assert(dfd != NULL && "dfd should not be NULL");
				assert(efd != s->sockfd &&
				    "EOF || ERROR on sockfd");
				assert(efd == dfd->fd);

				if (disable_rw(s->kq_hdl, efd)) {
					ERR("%d: %s(): disable_rw() failed: %m",
					    __LINE__, __func__);
					broadcast_shutdown(s);
					pthread_exit(NULL);
				}

				kill_socket(s, dfd);
				if (event[i].flags & EV_ERROR)
					ERR("%d: %s(): event error: %m",
					    __LINE__, __func__);
			} else if (efd == s->sockfd) {
				/*
				 * New connection incoming. dfd is NULL
				 * so we don't have to release it.
				 */
				assert(dfd == NULL && "dfd must NULL");
				assert(event[i].filter == EVFILT_READ);

				if (accept_new_connection(s))
					continue;
			} else if (event[i].filter == EVFILT_READ) {
				assert(dfd != NULL && "dfd should not be NULL");
				assert(efd != s->sockfd && "read on sockfd");
				assert(efd == dfd->fd);

				/*
				 * Disable the EVFILT_READ event so we
				 * don't get spammed by it.
				 */
				if (disable_fd(s->kq_hdl, efd, EVFILT_READ)) {
					ERR("%d: %s(): disable_fd() failed with: %m",
					    __LINE__, __func__);
					broadcast_shutdown(s);
					pthread_exit(NULL);
				}

				/*
				 * If efd did not state it ever wants
				 * READDATA to work on dtraced, we will
				 * simply ignore it and report a
				 * warning.
				 */
				if ((dfd->subs & DTD_SUB_READDATA) == 0) {
					WARN("%d: %s(): socket %d tried to "
					     "READDATA, but "
					     "is not subscribed (%lx)",
					    __LINE__, __func__, efd, dfd->subs);
					continue;
				}

				if (dispatch_event(s, &event[i])) {
					ERR("%d: %s(): dispatch_event() failed",
					    __LINE__, __func__);
					broadcast_shutdown(s);
					pthread_exit(NULL);
				}
			} else if (event[i].filter == EVFILT_WRITE) {
				assert(dfd != NULL && "dfd should not be NULL");
				assert(efd != s->sockfd && "write on sockfd");
				assert(efd == dfd->fd);

				if (disable_fd(kq, efd, EVFILT_WRITE)) {
					ERR("%d: %s(): disable_fd() failed with: %m",
					    __LINE__, __func__);
					broadcast_shutdown(s);
					pthread_exit(NULL);
				}

				dispatch = 0;

				LOCK(&s->joblistmtx);
				for (dtraced_job_t *job : s->joblist) {
					if (job->connsockfd == dfd)
						dispatch = 1;
				}

				/*
				 * If we have a job to dispatch to the
				 * socket, we tell a worker thread to
				 * actually do the action.
				 */
				if (dispatch != 0 &&
				    dispatch_event(s, &event[i])) {
					ERR("%d: %s(): dispatch_event() failed",
					    __LINE__, __func__);
					UNLOCK(&s->joblistmtx);
					broadcast_shutdown(s);
					pthread_exit(NULL);
				}

				UNLOCK(&s->joblistmtx);
			}
		}
	}

	pthread_exit(s);
}

int
setup_sockfd(struct dtraced_state *s)
{
	int err;
	struct sockaddr_un addr;
	size_t l;

	s->sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s->sockfd == -1) {
		ERR("%d: %s(): Failed to create unix: %m", __LINE__, __func__);
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		ERR("%d: %s(): Failed to copy %s into sockaddr (%zu)", __LINE__,
		    __func__, DTRACED_SOCKPATH, l);
		close(s->sockfd);
		s->sockfd = -1;
		err = mutex_destroy(&s->sockmtx);
		if (err != 0)
			ERR("%d: %s(): Failed to destroy sockmtx: %m", __LINE__,
			    __func__);

		return (-1);
	}

	if (remove(DTRACED_SOCKPATH) != 0) {
		if (errno != ENOENT) {
			ERR("%d: %s(): Failed to remove %s: %m", __LINE__,
			    __func__, DTRACED_SOCKPATH);
			return (-1);
		}
	}

	err = bind(s->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err != 0) {
		ERR("%d: %s(): Failed to bind to %d: %m", __LINE__, __func__,
		    s->sockfd);
		close(s->sockfd);
		s->sockfd = -1;
		err = mutex_destroy(&s->sockmtx);
		if (err != 0)
			ERR("%d: %s(): Failed to destroy sockmtx: %m", __LINE__,
			    __func__);

		return (-1);
	}

	return (0);
}

int
destroy_sockfd(struct dtraced_state *s)
{
	if (close(s->sockfd) != 0) {
		ERR("%d: %s(): Failed to close %d: %m", __LINE__, __func__,
		    s->sockfd);
		return (-1);
	}

	s->sockfd = -1;

	if (remove(DTRACED_SOCKPATH) != 0)
		ERR("%d: %s(): Failed to remove %s: %m", __LINE__, __func__,
		    DTRACED_SOCKPATH);

	return (0);
}
