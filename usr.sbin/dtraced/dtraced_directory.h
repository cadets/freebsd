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

#ifndef _DTRACED_DIRECTORY_H_
#define _DTRACED_DIRECTORY_H_

#include <dirent.h>

#include "dtraced_lock.h"

namespace dtraced {

extern char INBOUNDDIR[MAXPATHLEN];
extern char OUTBOUNDDIR[MAXPATHLEN];
extern char BASEDIR[MAXPATHLEN];


struct dir;
struct state;

typedef int (*foreach_fn_t)(struct dirent *, dir *);

struct dir {
	char *dirpath;		 /* directory path */
	int dirfd;		 /* directory filedesc */
	DIR *dir;		 /* directory pointer */
	char **existing_files;	 /* files that exist in the dir */
	size_t efile_size;	 /* vector size */
	size_t efile_len;	 /* number of elements */
	mutex_t dirmtx;		 /* directory mutex */
	foreach_fn_t processfn;	 /* function to process the dir */
	state *state; /* backpointer to state */
};

int         write_data(dir *, unsigned char *, size_t);
void        *listen_dir(void *);
int         populate_existing(struct dirent *, dir *);
int         file_foreach(DIR *, foreach_fn_t, dir *);
dir   *dtd_mkdir(const char *, foreach_fn_t);
void        dtd_closedir(dir *);
int         process_inbound(struct dirent *, dir *);
int         process_base(struct dirent *, dir *);
int         process_outbound(struct dirent *, dir *);

}

#endif // _DTRACED_DIRECTORY_H_
