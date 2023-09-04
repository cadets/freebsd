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
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>

#include "dtraced_chld.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

namespace dtraced {

void
manage_children(void *_s)
{
	state *s = (dtraced::state *)_s;
	pid_t pid;

	while (1) {
		/*
		 * Wait for a notification that we need to kill a process
		 */
		std::unique_lock lk { s->killmtx };
		s->killcv.wait(lk, [s] {
			return (!s->pids_to_kill.empty() || s->shutdown.load());
		});

		/*
		 * No need to unlock here due to RAII.
		 */
		if (unlikely(s->shutdown.load()))
			return;

		pid = s->pids_to_kill.front();
		s->pids_to_kill.pop();
		lk.unlock();

		{
			std::lock_guard lk { s->pidlistmtx };
			s->pidlist.erase(pid);
		}

		LOG("kill %d", pid);
		if (kill(pid, SIGTERM)) {
			assert(errno != EINVAL);
			assert(errno != EPERM);

			if (errno == ESRCH)
				ERR("pid %d does not exist", pid);
		}
	}
}

void
reap_children(void *_s)
{
	state *s = (dtraced::state *)_s;
	int status, rv;

	for (;;) {
		usleep(DTRACED_SLEEPTIME * 100);
		do {
			rv = waitpid(-1, &status, WNOHANG);
		} while (rv != -1 && rv != 0);

		if (s->shutdown.load() != 0)
			return;
	}
}

}
