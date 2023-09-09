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

#include <stdio.h>
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

namespace dtraced {

/*
 * Allocates a new job and populates the fields used in all the jobs. The caller
 * is responsible for filling out kind-specific fields.
 */
job *
dtraced_new_job(int job_kind, client_fd *dfdp)
{
	job *j;
	client_fd &dfd = *dfdp;

	j = new job;
	if (j == nullptr)
		return (nullptr);

	j->job = job_kind;
	j->connsockfd = dfdp;
	dfd.acquire();
	dtraced_tag_job(dfd.id, j);

	j->ident_str[sizeof(j->ident_str) - 1] = '\0';

	sprintf(j->ident_str, "%lx-%lx", j->identifier.job_initiator_id,
	    j->identifier.job_id);

	return (j);
}

static void
free_elfwrite(job *j)
{

	free(j->j.notify_elfwrite.path);
}

static void
free_cleanup(job *j)
{
	size_t i;

	for (i = 0; i < j->j.cleanup.n_entries; i++) {
		free(j->j.cleanup.entries[i]);
	}

	free(j->j.cleanup.entries);
}

void
dtraced_free_job(job *j)
{
	switch (j->job) {
	case NOTIFY_ELFWRITE:
		free_elfwrite(j);
		j->connsockfd->release();
		break;

	case KILL:
	case READ_DATA:
		j->connsockfd->release();
		break;

	case CLEANUP:
		free_cleanup(j);
		j->connsockfd->release();
		break;

	case SEND_INFO:
		break;

	default:
		break;
	}

	delete j;
}

const char *
dtraced_job_identifier(job *j)
{

	return ((const char *)j->ident_str);
}

}
