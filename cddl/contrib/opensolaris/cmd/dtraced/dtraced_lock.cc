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

#include <sys/param.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dtraced_errmsg.h"
#include "dtraced_lock.h"

#ifdef DTRACED_ROBUST
void
mutex_assert_owned(mutex_t *m)
{
	int err;

	errno = 0; /* Clear the errno to check the condition */
	err = pthread_mutex_trylock(pmutex_of(m));
	if (err == 0 || (err && errno != 0)) {
		ERR("%d: %s(): mutex %s is not owned: %m", __LINE__, __func__,
		    m->_name);
		abort();
	}
}
#endif

int
mutex_init(mutex_t *m, const pthread_mutexattr_t *attr,
    const char *name)
{
	size_t l;

	assert(m != NULL);

	if (name == NULL)
		return (-1);

	l = strlcpy(m->_name, name, MAXPATHLEN);
	if (l >= MAXPATHLEN)
		return (-1);

	return (pthread_mutex_init(&m->_m, attr));
}

int
mutex_destroy(mutex_t *m)
{

	return (pthread_mutex_destroy(&m->_m));
}

pthread_mutex_t *
pmutex_of(mutex_t *m)
{

	return (&m->_m);
}
