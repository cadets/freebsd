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

#include <pthread.h>

#include "dtraced.h"
#include "dtraced_directory.h"
#include "dtraced_lock.h"

#include <array>
#include <condition_variable>
#include <list>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_set>
#include <vector>

#define unlikely(x) __predict_false(x)

namespace dtraced {

struct job;

/*
 * dtraced state structure. This contains everything relevant to dtraced's
 * state management, such as files that exist, connected sockets, etc.
 */
struct state {
	const char **argv;	/* Needed in case we need to re-exec. */
	int ctrlmachine;	/* is this a control machine? */
	size_t threadpool_size; /* size of the thread pool (workers) */

	dir *inbounddir;  /* /var/ddtrace/inbound */
	dir *outbounddir; /* /var/ddtrace/outbound */
	dir *basedir;	  /* /var/ddtrace/base */

	std::thread inboundtd; /* inbound monitoring thread */
	std::thread basetd;    /* base monitoring thread */
	/* the outbound monitoring thread is the main thread */

	/*
	 * Sockets.
	 */
	std::mutex socklistmtx; /* mutex fos sockfds */

	/* list of sockets we know about */
	std::unordered_set<fd *> sockfds;

	/*
	 * Configuration socket.
	 */
	std::mutex sockmtx;  /* config socket mutex */
	std::thread socktd; /* config socket thread */
	int sockfd;	  /* config socket filedesc */
	sem_t socksema;	  /* config socket semaphore */

	/*
	 * dttransport fd and threads
	 */
	int dtt_fd;		/* dttransport filedesc */
	std::thread dtt_listentd; /* read() on dtt_fd */
	std::thread dtt_writetd;	/* write() on dtt_fd */

	/*
	 * Thread pool management.
	 */
	std::vector<std::thread> workers; /* thread pool for the joblist */
	std::mutex joblistmtx; /* joblist mutex */
	std::list<job *> joblist;
	std::mutex dispatched_jobsmtx; /* dispatched joblist mutex */

	/* jobs to be picked up by the workers */
	std::list<job *> dispatched_jobs;
	std::condition_variable dispatched_jobscv; /* dispatched joblist condvar */

	/*
	 * Children management.
	 */
	std::thread killtd; /* handle sending kill(SIGTERM) to the guest */
	std::mutex killmtx;  /* mutex of the kill list */
	std::queue<pid_t> pids_to_kill; /* a list of pids to kill */
	std::condition_variable killcv;		/* kill list condvar */
	std::thread reaptd;		/* handle reaping children */

	std::unordered_set<pid_t> pidlist; /* a list of pids running */
	std::mutex pidlistmtx;		   /* mutex of the pidlist */

	/*
	 * filedesc management.
	 */
	/* dead file descriptor list (to close) */
	std::unordered_set<fd *> deadfds;
	std::mutex deadfdsmtx; /* mutex for deadfds */
	std::thread closetd;  /* file descriptor closing thread */

	std::condition_variable jobcleancv; /* job cleaning thread condvar */
	std::thread jobcleantd;	   /* job cleaning thread */

	/*
	 * Consumer threads
	 */
	std::thread consumer_listentd; /* handle consumer messages */
	std::thread consumer_writetd;  /* send messages to consumers */

	std::atomic_int shutdown; /* shutdown flag */
	int nosha;		  /* do we want to checksum? */
	int kq_hdl;		  /* event loop kqueue */

	std::list<std::array<char, DTRACED_PROGIDENTLEN>> identlist;
	std::mutex identlistmtx; /* mutex protecting the ident list */
};

int init_state(state *, int, int, int, const char **);
int destroy_state(state *);

void _broadcast_shutdown(state *, const char *, int);
#define broadcast_shutdown(_a) (_broadcast_shutdown(_a, __FILE__, __LINE__))

}

#endif // _DTRACED_STATE_H_
