/*-
 * Copyright (c) 2020, 2021 Domagoj Stolfa
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

#ifndef _DT_TYPING_H_
#define _DT_TYPING_H_

#include <sys/dtrace.h>
#include <dtrace.h>

#define DTC_BOTTOM  -1
#define DTC_INT      0
#define DTC_STRUCT   1
#define DTC_STRING   2
#define DTC_FORWARD  3
#define DTC_UNION    4
#define DTC_ENUM     5

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <dt_dfg.hh>

#include <unordered_set>
#include <vector>

namespace dtrace {

template <typename T> using vec = std::vector<T>;
template <typename T> using uset = std::unordered_set<T>;

extern int dt_prog_infer_types(dtrace_hdl_t *, dtrace_prog_t *,
    dtrace_difo_t *);
extern int dt_infer_type(dfg_node *);
extern int dt_infer_type_subr(dfg_node *, node_vec *);
extern int dt_var_stack_typecheck(dfg_node *, dfg_node *,
    dtrace_difv_t *);
extern node_vec *dt_typecheck_stack(dfg_node *, vec<stackdata> &, int *);
extern dfg_node *dt_typecheck_regdefs(dfg_node *, node_set &, int *);

}

#endif /* _DT_TYPING_H_ */
