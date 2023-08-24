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

#ifndef _DTRACED_STATE_H_
#define _DTRACED_STATE_H_

#include <dt_list.h>
#include <pthread.h>

#include "dtraced.h"
#include "dtraced_directory.h"
#include "dtraced_lock.h"

#include <array>
#include <list>
#include <queue>
#include <unordered_set>

#define unlikely(x) __predict_false(x)

struct dtraced_job;
typedef struct dtraced_job dtraced_job_t;

/*
 * dtraced state structure. This contains everything relevant to dtraced's
 * state management, such as files that exist, connected sockets, etc.
 */
struct dtraced_state {
	const char **argv;      /* Needed in case we need to re-exec. */
	int ctrlmachine;        /* is this a control machine? */
	size_t threadpool_size; /* size of the thread pool (workers) */

	dtd_dir_t *inbounddir;  /* /var/ddtrace/inbound */
	dtd_dir_t *outbounddir; /* /var/ddtrace/outbound */
	dtd_dir_t *basedir;     /* /var/ddtrace/base */

	pthread_t inboundtd;    /* inbound monitoring thread */
	pthread_t basetd;       /* base monitoring thread */
	/* the outbound monitoring thread is the main thread */

	/*
	 * Sockets.
	 */
	mutex_t socklistmtx; /* mutex fos sockfds */

	/* list of sockets we know about */
	std::unordered_set<dtraced_fd_t *> sockfds;

	/*
	 * Configuration socket.
	 */
	mutex_t sockmtx;  /* config socket mutex */
	pthread_t socktd; /* config socket thread */
	int sockfd;       /* config socket filedesc */
	sem_t socksema;   /* config socket semaphore */

	/*
	 * dttransport fd and threads
	 */
	int dtt_fd;             /* dttransport filedesc */
	pthread_t dtt_listentd; /* read() on dtt_fd */
	pthread_t dtt_writetd;  /* write() on dtt_fd */

	/*
	 * Thread pool management.
	 */
	pthread_t *workers;         /* thread pool for the joblist */
	mutex_t joblistmtx;         /* joblist mutex */
	std::list<dtraced_job_t *> joblist;
	mutex_t dispatched_jobsmtx; /* dispatched joblist mutex */

	/* jobs to be picked up by the workers */
	std::list<dtraced_job_t *> dispatched_jobs;
	pthread_cond_t dispatched_jobscv;   /* dispatched joblist condvar */

	/*
	 * Children management.
	 */
	pthread_t killtd;      /* handle sending kill(SIGTERM) to the guest */
	mutex_t killmtx;  /* mutex of the kill list */
	std::queue<pid_t> pids_to_kill; /* a list of pids to kill */
	pthread_cond_t killcv; /* kill list condvar */
	pthread_t reaptd;      /* handle reaping children */

	std::unordered_set<pid_t> pidlist; /* a list of pids running */
	mutex_t pidlistmtx;  /* mutex of the pidlist */

	/*
	 * filedesc management.
	 */
	 /* dead file descriptor list (to close) */
	std::unordered_set<dtraced_fd_t *> deadfds;
	mutex_t deadfdsmtx; /* mutex for deadfds */
	pthread_t closetd;  /* file descriptor closing thread */

	pthread_cond_t jobcleancv;  /* job cleaning thread condvar */
	pthread_t jobcleantd;       /* job cleaning thread */

	/*
	 * Consumer threads
	 */
	pthread_t consumer_listentd; /* handle consumer messages */
	pthread_t consumer_writetd;  /* send messages to consumers */

	std::atomic_int shutdown;    /* shutdown flag */
	int nosha;                   /* do we want to checksum? */
	int kq_hdl;                  /* event loop kqueue */

	std::list<std::array<char, DTRACED_PROGIDENTLEN>> identlist;
	mutex_t identlistmtx;        /* mutex protecting the ident list */
};

int init_state(struct dtraced_state *, int, int, int, const char **);
int destroy_state(struct dtraced_state *);
void _broadcast_shutdown(struct dtraced_state *, const char *, int);

#define broadcast_shutdown(_a)	(_broadcast_shutdown(_a,__FILE__,__LINE__))

#endif // _DTRACED_STATE_H_
