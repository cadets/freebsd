/*-
 * Copyright (c) 2020 Domagoj Stolfa
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

#ifndef _DT_IFG_H_
#define _DT_IFG_H_

#include <sys/dtrace.h>

#include <dtrace.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>

#include <dt_basic_block.hh>
#include <dt_typefile.hh>
#include <dt_dfg.hh>

#ifndef __cplusplus
#error "This file should only be included from C++"
#endif

#include <optional>
#include <set>
#include <unordered_set>
#include <vector>

namespace dtrace {

class dfg_node;

template <typename T> using uset = std::unordered_set<T>;
template <typename T> using vec = std::vector<T>;
using node_set = uset<dfg_node *>;
using node_vec = vec<dfg_node *>;

enum dfg_node_kind {
	DT_NKIND_IGNORE = -1,
	DT_NKIND_REG = 1,
	DT_NKIND_VAR = 2,
	DT_NKIND_STACK = 3
};

class dfg_node_data {
    public:
	dfg_node_kind kind = DT_NKIND_IGNORE; /* kind (see below) */

    private:
	union {
		uint8_t rd; /* DT_RKIND_REG */
		struct {    /* DT_RKIND_VAR */
			uint16_t var;
			uint8_t scope;
			uint8_t varkind;
		} v;
	} u;

    public:
	uint8_t &rd() { return (this->u.rd); }
	uint16_t &var() { return (this->u.v.var); }
	uint8_t &scope() { return (this->u.v.scope); }
	uint8_t &varkind() { return (this->u.v.varkind); }
};

class stackdata {
    public:
	vec<basic_block *> identifier;
	node_vec nodes_on_stack;

    public:
	stackdata(vec<basic_block *> &);
	~stackdata() = default;
};

/*
 * Data-flow graph node.
 */
class dfg_node {
    public:
	size_t uidx; /* index of the use site */

	/*
	 * Vectors of various IFG nodes. They contain backpointers to various
	 * kinds of definitions in the IFG.
	 */
	node_set r1_defs;      /* type flow for r1 */
	node_set r2_defs;      /* type flow for r2 */
	node_set r1_data_defs; /* data flow for r1 */
	node_set r2_data_defs; /* data flow for r2 */
	node_set var_defs;     /* vector of variable defns in DIFO */
	node_set r1_children;  /* which r1s do we define */
	node_set r2_children;  /* which r2s do we define */
	node_set usetx_defs;   /* usetx insn vector defining the node */

	vec<dtrace_difv_t *> var_sources; /* variable origin (if exists) */

	int d_type = DIF_TYPE_NONE;	/* D type */
	typefile *tf = nullptr;		/* reference to the type's type file */
	ctf_id_t ctfid = CTF_ERR;	/* CTF type */
	char *sym = nullptr;		/* symbol (if applicable) */
	ctf_membinfo_t *mip = nullptr;	/* CTF member info (type, offs) */

	dtrace_hdl_t *dtp = nullptr;
	dtrace_ecbdesc_t *edp = nullptr;	/* node's ecbdesc */
	dtrace_prog_t *program = nullptr;	/* program this node belongs to */
	dtrace_difo_t *difo = nullptr;		/* DIFO which this node belongs to */
	basic_block *bb = nullptr;		 /* basic block that the node is in */
	vec<stackdata> stacks;		 /* list of pushtr/pushtv nodes */
	dfg_node_data node_data;	 /* node data (reg, var, stack) */
	bool relocated = false;			 /* relocated or not? */
	bool isnull = true;			 /* can this node contain NULL? */
	std::optional<uint64_t> integer; /* integer value from setx */

    public:
	dfg_node(dtrace_hdl_t *, dtrace_prog_t *, dtrace_ecbdesc_t *,
	    dtrace_difo_t *, basic_block *, uint_t);
	~dfg_node() = default;

	dif_instr_t *difo_buf() { return (this->difo->dtdo_buf); }
	uint8_t get_rd(void);
	dif_instr_t get_instruction(void) const;
	dfg_node *find_child(dfg_node *);
};

extern void get_node_data(dif_instr_t, dfg_node_data &);
extern int dt_compute_dfg(dtrace_hdl_t *, dtrace_prog_t *, dtrace_ecbdesc_t *,
    dtrace_difo_t *);
}

#endif /* _DT_IFG_H_ */
