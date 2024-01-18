/*-
 * Copyright (c) 2024 Domagoj Stolfa
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

#ifndef _DT_TYPING_HELPERS_HH_
#define _DT_TYPING_HELPERS_HH_

#include <sys/types.h>
#include <sys/ctf.h>

#include <dtrace.h>
#include <dt_program.h>
#include <dt_typefile.hh>

#define SUBTYPE_NONE  0
#define SUBTYPE_EQUAL (1 << 0)
#define SUBTYPE_FST   (1 << 1)
#define SUBTYPE_SND   (1 << 2)
#define SUBTYPE_ANY   (SUBTYPE_EQUAL | SUBTYPE_FST | SUBTYPE_SND)

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

namespace dtrace {

extern dtrace_hdl_t *g_dtp;
extern dtrace_prog_t *g_pgp;

extern ctf_id_t dt_type_strip_ref(typefile *, ctf_id_t &, size_t &);
extern ctf_id_t dt_type_strip_typedef(typefile *, ctf_id_t *);
extern int dt_ctf_type_compare(typefile *, ctf_id_t, typefile *,
    ctf_id_t);
extern int dt_type_subtype(typefile *, ctf_id_t, typefile *, ctf_id_t,
    int *);
extern const char *dt_class_name(int);
extern int dt_get_class(typefile *, ctf_id_t, int);
extern int dt_type_compare(dfg_node *, dfg_node *);
extern typefile *dt_get_typename_tfcheck(dfg_node *, typefile **,
    size_t, char *, size_t, const char *);
extern void dt_get_typename(dfg_node *, char *, size_t, const char *);
extern int dt_typecheck_string(dtrace_hdl_t *, int, int, ctf_id_t, ctf_id_t,
    typefile *, typefile *);
extern int dt_typecheck_stringii(dtrace_hdl_t *, dfg_node *,
    dfg_node *);
extern int dt_typecheck_stringiv(dtrace_hdl_t *, dfg_node *,
    dtrace_difv_t *);
extern ctf_membinfo_t *dt_mip_from_sym(dfg_node *);
extern ctf_membinfo_t *dt_mip_by_offset(dtrace_hdl_t *, typefile *,
    ctf_id_t, uint64_t);
extern ctf_id_t dt_autoresolve_ctfid(const char *, const char *,
    typefile **);

}

#endif /* _DT_TYPING_HELPERS_HH_ */
