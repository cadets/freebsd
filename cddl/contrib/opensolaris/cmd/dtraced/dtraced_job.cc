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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_cleanupjob.h"
#include "dtraced_connection.h"
#include "dtraced_elfjob.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_killjob.h"
#include "dtraced_lock.h"
#include "dtraced_readjob.h"
#include "dtraced_sendinfojob.h"
#include "dtraced_state.h"

/*
 * Allocates a new job and populates the fields used in all the jobs. The caller
 * is responsible for filling out kind-specific fields.
 */
dtraced_job_t *
dtraced_new_job(int job_kind, dtraced_fd_t *dfd)
{
	dtraced_job_t *j = NULL;

	j = (dtraced_job_t *)malloc(sizeof(dtraced_job_t));
	if (j == NULL)
		return (NULL);

	memset(j, 0, sizeof(dtraced_job_t));

	j->job = job_kind;
	j->connsockfd = dfd;
	fd_acquire(dfd);
	dtraced_tag_job(dfd->id, j);

	j->ident_str[sizeof(j->ident_str) - 1] = '\0';

	sprintf(j->ident_str, "%lx-%lx", j->identifier.job_initiator_id,
	    j->identifier.job_id);

	return (j);
}

static void
free_elfwrite(dtraced_job_t *j)
{

	free(j->j.notify_elfwrite.path);
}

static void
free_cleanup(dtraced_job_t *j)
{
	size_t i;

	for (i = 0; i < j->j.cleanup.n_entries; i++) {
		free(j->j.cleanup.entries[i]);
	}

	free(j->j.cleanup.entries);
}

void
dtraced_free_job(dtraced_job_t *j)
{
	switch (j->job) {
	case NOTIFY_ELFWRITE:
		free_elfwrite(j);
		fd_release(j->connsockfd);
		break;

	case KILL:
	case READ_DATA:
		fd_release(j->connsockfd);
		break;

	case CLEANUP:
		free_cleanup(j);
		fd_release(j->connsockfd);
		break;

	case SEND_INFO:
		break;

	default:
		ERR("%d: %s(): free of unknown job kind: %d", __LINE__,
		    __func__, j->job);
		break;
	}

	free(j);
}

/*
 * NOTE: dispatch_event assumes that event has already been handled correctly in
 * the main loop.
 */
int
dispatch_event(struct dtraced_state *s, struct kevent *ev)
{
	dtraced_fd_t *dfd;
	dtraced_job_t *job;
	int efd;

	efd = (int)ev->ident;

	if (ev->filter == EVFILT_READ) {
		dfd = (dtraced_fd_t *)ev->udata;

		/*
		 * Read is a little bit more complicated than write, because we
		 * have to read in the actual event and put it in the
		 * /var/ddtrace/base directory for the directory monitoring
		 * kqueues to wake up and process it further.
		 */
		job = dtraced_new_job(READ_DATA, dfd);
		if (job == NULL) {
			ERR("%d: %s(): dtraced_new_job() failed with: %m",
			    __LINE__, __func__);
			abort();
		}

		LOCK(&s->dispatched_jobsmtx);
		s->dispatched_jobs.push_front(job);

		DEBUG("%d: %s(): job %p: dispatch EVFILT_READ on %d", __LINE__,
		    __func__, job, dfd->fd);

		SIGNAL(&s->dispatched_jobscv);
		UNLOCK(&s->dispatched_jobsmtx);

	} else if (ev->filter == EVFILT_WRITE) {
		/*
		 * Go through the joblist, and if we find a job which has our
		 * file descriptor as the destination, we put it in the dispatch
		 * list.
		 */

		/*
		 * Assert that the mutex is actually owned. For EVFILT_WRITE, we
		 * expect to be called with the lock held because the caller
		 * will be modifying the joblist regardless.
		 */
		mutex_assert_owned(&s->joblistmtx);
		for (auto it = s->joblist.begin(); it != s->joblist.end();) {
			job = *it;
			dfd = job->connsockfd;
			if (dfd->fd == efd) {
				it = s->joblist.erase(it);
				LOCK(&s->dispatched_jobsmtx);
				s->dispatched_jobs.push_back(job);
				SIGNAL(&s->dispatched_jobscv);
				UNLOCK(&s->dispatched_jobsmtx);
			} else
				++it;
		}

	} else {
		ERR("%d: %s(): Unexpected event flags: %d", __LINE__, __func__,
		    ev->flags);
		return (-1);
	}

	return (0);
}

void *
process_joblist(void *_s)
{
	struct dtraced_job *curjob;
	struct dtraced_state *s = (struct dtraced_state *)_s;
#ifdef DTRACED_DEBUG
	const char *jobname[] = {
		[0]               = "NONE",
		[NOTIFY_ELFWRITE] = "NOTIFY_ELFWRITE",
		[KILL]            = "KILL",
		[READ_DATA]       = "READ_DATA",
		[CLEANUP]         = "CLEANUP",
		[SEND_INFO]       = "SEND_INFO"
	};
#endif /* DTRACED_DEBUG */
	int _shutdown = 0;

	while (1) {
		LOCK(&s->dispatched_jobsmtx);
		while (s->dispatched_jobs.empty() &&
		    (_shutdown = s->shutdown.load()) == 0) {
			WAIT(&s->dispatched_jobscv,
			    pmutex_of(&s->dispatched_jobsmtx));
		}

		if (unlikely(_shutdown == 1)) {
			UNLOCK(&s->dispatched_jobsmtx);
			break;
		}

		curjob = s->dispatched_jobs.front();
		s->dispatched_jobs.pop_front();
		UNLOCK(&s->dispatched_jobsmtx);

		if (curjob->job >= 0 && curjob->job <= JOB_LAST)
			DEBUG("%d: %s(): processing %s[%s]", __LINE__, __func__,
			    jobname[curjob->job],
			    dtraced_job_identifier(curjob));
		else
			ERR("%d: %s(): job %u[%s] out of bounds", __LINE__,
			    __func__, curjob->job,
			    dtraced_job_identifier(curjob));

		DEBUG("%d: %s: job %s: processing (kind=%d)\n", __LINE__,
		    __func__, dtraced_job_identifier(curjob), curjob->job);
		switch (curjob->job) {
		case READ_DATA:
			handle_read_data(s, curjob);
			break;

		case KILL:
			handle_kill(s, curjob);
			break;

		case NOTIFY_ELFWRITE:
			handle_elfwrite(s, curjob);
			break;

		case CLEANUP:
			handle_cleanup(s, curjob);
			break;

		case SEND_INFO:
			handle_sendinfo(s, curjob);
			break;

		default:
			ERR("%d: %s(): Unknown job: %d", __LINE__, __func__,
			    curjob->job);
			abort();
		}

		dtraced_free_job(curjob);
	}

	pthread_exit(s);
}

const char *
dtraced_job_identifier(dtraced_job_t *j)
{

	return ((const char *)j->ident_str);
}

void *
clean_jobs(void *_s)
{
	struct dtraced_state *s = (struct dtraced_state *)_s;
	int woken;

	while (1) {
		woken = 0;
		LOCK(&s->deadfdsmtx);
		while (s->shutdown.load() == 0 &&
		    (s->deadfds.empty() || woken == 0)) {
			WAIT(&s->jobcleancv, pmutex_of(&s->deadfdsmtx));
			woken = 1;
		}

		if (unlikely(s->shutdown.load() == 1)) {
			UNLOCK(&s->deadfdsmtx);
			pthread_exit(_s);
		}

		/*
		 * Delete any jobs that our dead file descriptors have started.
		 * We don't need to do anything with them, as the initiating
		 * process is gone.
		 */
		for (dtraced_fd_t *dfd : s->deadfds) {
			LOCK(&s->joblistmtx);
			for (auto it = s->joblist.begin();
			     it != s->joblist.end();) {
				dtraced_job_t *j = *it;
				if (j->identifier.job_initiator_id == dfd->id) {
					it = s->joblist.erase(it);
					dtraced_free_job(j);
				} else
					++it;
			}
			UNLOCK(&s->joblistmtx);

			dfd->cleaned_up = 1;
		}
		UNLOCK(&s->deadfdsmtx);
	}

	pthread_exit(_s);
}
