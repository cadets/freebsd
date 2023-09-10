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

#ifndef _DTRACED_CONNECTION_H_
#define _DTRACED_CONNECTION_H_

#include <sys/types.h>

#include <execinfo.h>
#include <unistd.h>

#include "_dtraced_connection.h"
#include "dtraced.h"
#include "dtraced_errmsg.h"
#include "dtraced_misc.h"

#include <atomic>

#define DTRACED_FDIDENTLEN             128ull

namespace dtraced {

class state;

inline void
client_fd::acquire(void)
{

	this->count.fetch_add(1);
}

inline void
client_fd::release(void)
{
	int count = this->count.fetch_sub(1);
	if (unlikely(count < 0)) {
		ERR("%p count (= %d) < 0: aborting.", this, count);
		abort();
	}
}

inline bool
client_fd::is_dead(void)
{

	return (this->count.load() == 0);
}

inline bool
client_fd::is_subscribed(uint32_t which)
{

	return ((this->subs & which) != 0);
}

inline int
client_fd::get_fd(void)
{

	return (this->fd);
}

int  send_ack(int);
int  send_nak(int);
int  enable_fd(int, int, int, void *);
int  reenable_fd(int, int, int);
int  disable_fd(int, int, int);
int  disable_rw(int, int);
}

#endif // _DTRACED_CONNECTION_H_
