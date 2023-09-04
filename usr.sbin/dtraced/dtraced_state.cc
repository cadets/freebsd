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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_chld.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_state.h"

namespace dtraced {

static int
setup_threads(state *s)
{
	size_t i;

	s->workers.resize(s->threadpool_size);
	for (i = 0; i < s->threadpool_size; i++) {
		s->workers[i] = std::thread(process_joblist, s);
	}

	sem_init(&s->socksema, 0, 0);

	if (s->ctrlmachine == 0) {
		s->dtt_listentd = std::thread(dtraced::listen_dttransport, s);
		s->dtt_writetd = std::thread(dtraced::write_dttransport, s);
	}

	s->socktd = std::thread(process_consumers, s);
	s->inboundtd = std::thread(listen_dir, s->inbounddir);
	s->basetd = std::thread(listen_dir, s->basedir);
	s->killtd = std::thread(manage_children, s);
	s->reaptd = std::thread(reap_children, s);
	s->closetd = std::thread(close_filedescs, s);
	s->jobcleantd = std::thread(clean_jobs, s);

	return (0);
}

int
init_state(state *s, int ctrlmachine, int nosha, int n_threads,
    const char **argv)
{
	int err;

	s->argv = argv;
	s->sockfd = -1;
	s->ctrlmachine = ctrlmachine;
	s->nosha = nosha;
	s->threadpool_size = n_threads;

	if (s->ctrlmachine == 0) {
		/* We close dttransport on exec. */
		s->dtt_fd = open("/dev/dttransport",
		    O_RDWR | O_CLOEXEC | O_NONBLOCK);
		if (s->dtt_fd == -1) {
			ERR("Failed to open /dev/dttransport: %m");
			return (-1);
		}
	}

	s->outbounddir = dtd_mkdir(OUTBOUNDDIR, &process_outbound);
	if (s->outbounddir == NULL) {
		ERR("Failed creating outbound directory: %m");
		return (-1);
	}

	s->inbounddir = dtd_mkdir(INBOUNDDIR, &process_inbound);
	if (s->inbounddir == NULL) {
		ERR("Failed creating inbound directory: %m");
		return (-1);
	}

	s->basedir = dtd_mkdir(BASEDIR, &process_base);
	if (s->basedir == NULL) {
		ERR("Failed creating base directory: %m");
		return (-1);
	}

	s->outbounddir->state = s;
	s->inbounddir->state = s;
	s->basedir->state = s;

	if (setup_sockfd(s) != 0) {
		ERR("Failed to set up the socket");
		return (-1);
	}

	err = file_foreach(s->outbounddir->dir,
	    populate_existing, s->outbounddir);
	if (err != 0) {
		ERR("Failed to populate outbound existing files");
		return (-1);
	}

	err = file_foreach(s->inbounddir->dir,
	    populate_existing, s->inbounddir);
	if (err != 0) {
		ERR("Failed to populate inbound existing files");
		return (-1);
	}

	err = file_foreach(s->basedir->dir, populate_existing, s->basedir);
	if (err != 0) {
		ERR("Failed to populate base existing files");
		return (-1);
	}

	err = setup_threads(s);
	if (err != 0) {
		ERR("Failed to set up threads");
		return (-1);
	}

	return (0);
}

int
destroy_state(state *s)
{
	size_t i;

	/*
	 * Give all the threads a chance to stop.
	 */
	s->socktd.join();
	if (s->ctrlmachine == 0) {
		s->dtt_listentd.join();
		s->dtt_writetd.join();
	}

	s->inboundtd.join();
	s->basetd.join();

	{
		std::lock_guard lk { s->dispatched_jobsmtx };
		s->dispatched_jobscv.notify_all();
	}

	for (i = 0; i < s->threadpool_size; i++) {
		s->workers[i].join();
	}

	s->killtd.join();
	s->reaptd.join();
	s->closetd.join();
	s->jobcleantd.join();

	{
		std::lock_guard lk { s->joblistmtx };
		for (; !s->joblist.empty(); s->joblist.pop_front())
			dtraced_free_job(s->joblist.front());
	}

	{
		std::lock_guard { s->dispatched_jobsmtx };
		for (; !s->dispatched_jobs.empty();
		     s->dispatched_jobs.pop_front())
			dtraced_free_job(s->dispatched_jobs.front());
	}

	dtd_closedir(s->outbounddir);
	dtd_closedir(s->inbounddir);
	dtd_closedir(s->basedir);

	sem_destroy(&s->socksema);

	destroy_sockfd(s);
	s->sockfd = -1;

	if (s->ctrlmachine == 0) {
		close(s->dtt_fd);
		s->dtt_fd = -1;
	}

	return (0);
}

void
_broadcast_shutdown(state *s, const char *errfile, int errline)
{
	fprintf(stderr, "%s (line %d): broadcasting shutdown", errfile, errline);
	s->shutdown.store(1);

	{
		std::lock_guard lk { s->dispatched_jobsmtx };
		s->dispatched_jobscv.notify_all();
	}

	{
		std::lock_guard lk { s->killmtx };
		s->killcv.notify_all();
	}

	{
		std::lock_guard lk { s->deadfdsmtx };
		s->jobcleancv.notify_all();
	}
}

}
