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

#include <sys/types.h>
#include <sys/dtrace.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>


#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_impl.h>
#include <dt_linker_subr.hh>
#include <dt_program.h>
#include <dtrace.h>

#include <stack>
#include <unordered_map>
#include <iterator>
#include <unordered_set>

namespace dtrace {

template <typename T> using uset = std::unordered_set<T>;
template <typename T> using uptr = std::unique_ptr<T>;
template <typename K, typename T> using hashmap = std::unordered_map<K, T>;

stackdata::stackdata(vec<basic_block *> &ident)
    : identifier(ident)
{
}

dfg_node::dfg_node(dtrace_hdl_t *_dtp, dtrace_prog_t *pgp,
    dtrace_ecbdesc_t *_edp, dtrace_difo_t *_difo, basic_block *_bb, uint_t idx)
    : dtp(_dtp)
    , program(pgp)
    , edp(_edp)
    , difo(_difo)
    , bb(_bb)
    , uidx(idx)
    , d_type(-1)
    , sym(nullptr)
    , ctfid(CTF_ERR)
    , mip(nullptr)
{
}

void
get_node_data(dif_instr_t instr, dfg_node_data &data)
{
	uint8_t opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
	case DIF_OP_USETX:
	case DIF_OP_TYPECAST:
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
	case DIF_OP_NOT:
	case DIF_OP_MOV:
	case DIF_OP_LDSB:
	case DIF_OP_LDSH:
	case DIF_OP_LDSW:
	case DIF_OP_LDUB:
	case DIF_OP_LDUH:
	case DIF_OP_LDUW:
	case DIF_OP_LDX:
	case DIF_OP_SETX:
	case DIF_OP_SETS:
	case DIF_OP_LDGA:
	case DIF_OP_LDGS:
	case DIF_OP_LDTA:
	case DIF_OP_LDTS:
	case DIF_OP_SRA:
	case DIF_OP_CALL:
	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_LDLS:
	case DIF_OP_ALLOCS:
	case DIF_OP_COPYS:
	case DIF_OP_ULDSB:
	case DIF_OP_ULDSH:
	case DIF_OP_ULDSW:
	case DIF_OP_ULDUB:
	case DIF_OP_ULDUH:
	case DIF_OP_ULDUW:
	case DIF_OP_ULDX:
	case DIF_OP_RLDSB:
	case DIF_OP_RLDSH:
	case DIF_OP_RLDSW:
	case DIF_OP_RLDUB:
	case DIF_OP_RLDUH:
	case DIF_OP_RLDUW:
	case DIF_OP_RLDX:
		data.kind = DT_NKIND_REG;
		data.rd() = DIF_INSTR_RD(instr);
		break;

	case DIF_OP_STGS:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_GLOBAL;
		data.varkind() = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STGAA:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_GLOBAL;
		data.varkind() = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTAA:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_THREAD;
		data.varkind() = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTS:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_THREAD;
		data.varkind() = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STLS:
		data.kind = DT_NKIND_VAR;
		data.var() = DIF_INSTR_VAR(instr);
		data.scope() = DIFV_SCOPE_LOCAL;
		data.varkind() = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
		data.kind = DT_NKIND_STACK;

	default:
		break;
	}
}

/*
 * This method assumes it's being called with a node `n` that is an
 * instruction with a destination register.
 */
uint8_t
dfg_node::get_rd(void)
{

	return (DIF_INSTR_RD(this->difo->dtdo_buf[this->uidx]));
}

dif_instr_t
dfg_node::get_instruction(void) const
{

	return (this->difo->dtdo_buf[this->uidx]);
}

static bool
dt_usite_uses_stack(dfg_node *n)
{
	dif_instr_t instr;
	uint8_t op;

	instr = n->get_instruction();
	op = DIF_INSTR_OP(instr);

	switch (op) {
	case DIF_OP_CALL:
	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_STTS:
	case DIF_OP_LDTS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
		return (true);

	default:
		break;
	}

	return (false);
}

static bool
dt_usite_contains_var(dfg_node *n, dfg_node_data &data)
{
	dif_instr_t instr;
	uint16_t v, var;
	uint8_t opcode, varkind, scope;

	instr = n->get_instruction();
	opcode = DIF_INSTR_OP(instr);

	var = data.var();
	scope = data.scope();
	varkind = data.varkind();

	switch (opcode) {
	case DIF_OP_LDGA:
		v = DIF_INSTR_R1(instr);

		if (scope != DIFV_SCOPE_GLOBAL)
			return (false);

		if (varkind != DIFV_KIND_ARRAY)
			return (false);

		if (v == var)
			return (true);
		break;

	case DIF_OP_LDTA:
		v = DIF_INSTR_R1(instr);

		if (scope != DIFV_SCOPE_THREAD)
			return (false);

		if (varkind != DIFV_KIND_ARRAY)
			return (false);

		if (v == var)
			return (true);
		break;

	case DIF_OP_LDGS:
		v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_GLOBAL)
			return (false);

		if (varkind != DIFV_KIND_SCALAR)
			return (false);

		if (v == var)
			return (true);
		break;

	case DIF_OP_LDGAA:
		v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_GLOBAL)
			return (false);

		if (varkind != DIFV_KIND_ARRAY)
			return (false);

		if (v == var)
			return (true);
		break;

	case DIF_OP_LDTAA:
		v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_THREAD)
			return (false);

		if (varkind != DIFV_KIND_ARRAY)
			return (false);

		if (v == var)
			return (true);
		break;

	case DIF_OP_LDTS:
		v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_THREAD)
			return (false);

		if (varkind != DIFV_KIND_SCALAR)
			return (false);

		if (v == var)
			return (true);
		break;

	case DIF_OP_LDLS:
		v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_LOCAL)
			return (false);

		if (varkind != DIFV_KIND_SCALAR)
			return (false);

		if (v == var)
			return (true);
		break;

	default:
		break;
	}

	return (false);
}

static bool
dt_usite_contains_reg(dfg_node *n, dfg_node *curnode, uint8_t rd,
    int *r1, int *r2)
{
	dif_instr_t instr = 0;
	uint8_t rs = 0, _rd = 0, _r1 = 0, _r2 = 0, opcode = 0;
	dif_instr_t curinstr;
	uint8_t curop;
	int check;

	curinstr = curnode->get_instruction();
	instr = n->get_instruction();

	*r1 = 0;
	*r2 = 0;

	opcode = DIF_INSTR_OP(instr);
	curop = DIF_INSTR_OP(curinstr);

	if (curop == DIF_OP_CALL)
		check = dt_subr_clobbers(DIF_INSTR_SUBR(curinstr));
	else
		check = 1;

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
	case DIF_OP_LDSB:
	case DIF_OP_LDSH:
	case DIF_OP_LDSW:
	case DIF_OP_LDUB:
	case DIF_OP_LDUH:
	case DIF_OP_LDUW:
	case DIF_OP_LDX:
	case DIF_OP_ULDSB:
	case DIF_OP_ULDSH:
	case DIF_OP_ULDSW:
	case DIF_OP_ULDUB:
	case DIF_OP_ULDUH:
	case DIF_OP_ULDUW:
	case DIF_OP_ULDX:
	case DIF_OP_RLDSB:
	case DIF_OP_RLDSH:
	case DIF_OP_RLDSW:
	case DIF_OP_RLDUB:
	case DIF_OP_RLDUH:
	case DIF_OP_RLDUW:
	case DIF_OP_RLDX:
	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
	case DIF_OP_TYPECAST:
		rs = DIF_INSTR_RS(instr);
		if (check && rd == rs)
			*r1 = 1;
		break;

	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
	case DIF_OP_SRA:
 	case DIF_OP_COPYS:
		_r1 = DIF_INSTR_R1(instr);
		_r2 = DIF_INSTR_R2(instr);

		if (check && _r1 == rd)
			*r1 = 1;
		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_NOT:
	case DIF_OP_MOV:
	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX:
		_r1 = DIF_INSTR_R1(instr);
		_r2 = DIF_INSTR_RD(instr);

		if (check && _r1 == rd)
			*r1 = 1;
		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_LDGA:
	case DIF_OP_LDTA:
	case DIF_OP_ALLOCS:
		_r2 = DIF_INSTR_R2(instr);

		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_STGS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
		_r2 = DIF_INSTR_RS(instr);

		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_RET:
		_rd = DIF_INSTR_RD(instr);

		if (check && _rd == rd)
			*r1 = 1;
		break;

	default:
		break;
	}

	return (*r1 != 0 || *r2 != 0);
}

static bool
dt_update_nodes_bb_var(dtrace_difo_t *difo, basic_block *bb,
    dfg_node_data &data, dfg_list::iterator pos)
{
	dif_instr_t instr;
	int v;
	dfg_node *curnode, *n;

	v = 0;
	curnode = pos->get();

	for (; pos != dfg_nodes.end(); ++pos) {
		n = pos->get();
		instr = n->get_instruction();

		if (n == curnode)
			continue;

		if (n->difo != bb->difo)
			continue;

		/*
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (curnode->uidx >= n->uidx)
			continue;

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		if (dt_usite_contains_var(n, data)) {
			n->var_defs.insert(curnode);
		}

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (dt_clobbers_var(instr, data))
			return (true);
	}

	return (false);
}

static int
dt_update_nodes_bb_stack(vec<basic_block *> &bb_path, dtrace_difo_t *difo,
    basic_block *bb, dfg_list::iterator pos)
{
	dfg_node *n, *curnode;
	uint8_t op;
	dif_instr_t instr;
	int n_pushes;

	n_pushes = 1;
	curnode = pos->get();

	for (; pos != dfg_nodes.end(); ++pos) {
		n = pos->get();
		instr = n->get_instruction();
		op = DIF_INSTR_OP(instr);

		if (n == curnode)
			continue;

		if (n->difo != bb->difo)
			continue;

		if (n_pushes < 1)
			errx(EXIT_FAILURE,
			    "dt_update_nodes_bb_stack(): n_pushes (%d) < 0 on "
			    "DIFO %p (node %zu)",
			    n_pushes, n->difo, n->uidx);

		if (n->uidx <= curnode->uidx)
			continue;

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		if (op == DIF_OP_FLUSHTS)
			return (1);

		if (n_pushes == 1 && op == DIF_OP_POPTS)
			return (1);

		if (n_pushes > 1 && op == DIF_OP_POPTS) {
			n_pushes--;
			continue;
		}

		if (op == DIF_OP_PUSHTV || op == DIF_OP_PUSHTR) {
			n_pushes++;
			continue;
		}

		if (dt_usite_uses_stack(n)) {
			auto stack_idx = dt_get_stack(bb_path, n);
			assert(stack_idx != -1);
			n->stacks[stack_idx].nodes_on_stack.push_back(curnode);
		}
	}

	return (0);
}

static int
dt_update_nodes_bb_reg(dtrace_difo_t *difo, basic_block *bb, uint8_t rd,
    dfg_list::iterator pos, int *seen_typecast)
{
	dfg_node *n, *curnode;
	int r1, r2;
	dif_instr_t instr, curinstr;
	uint8_t opcode, curop;
	int clobbers;

	r1 = 0;
	r2 = 0;
	curnode = pos->get();

	if (bb->difo != difo)
		return (0);

	curinstr = curnode->get_instruction();
	curop = DIF_INSTR_OP(curinstr);

	if (dt_usite_contains_reg(curnode, curnode, 0, &r1, &r2)) {
		assert(r1 == 1 || r2 == 1);
		if (r1 == 1) {
			curnode->r1_defs.insert(r0node);
		}

		if (r2 == 1) {
			curnode->r2_defs.insert(r0node);
		}
	}

	r1 = r2 = 0;
	for (; pos != dfg_nodes.end(); ++pos) {
		n = pos->get();
		instr = n->get_instruction();
		opcode = DIF_INSTR_OP(instr);

		if (n == curnode)
			continue;

		if (n->difo != bb->difo)
			continue;

		/*
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (curnode->uidx >= n->uidx)
			continue;

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		if (dt_usite_contains_reg(n, curnode, rd, &r1, &r2)) {
			assert(r1 == 1 || r2 == 1);
			if (r1 == 1 && *seen_typecast == 0) {
				n->r1_defs.insert(curnode);
				curnode->r1_children.insert(n);
			}

			if (r2 == 1 && *seen_typecast == 0) {
				n->r2_defs.insert(curnode);
				curnode->r2_children.insert(n);
			}

			if (r1 == 1 && curop != DIF_OP_TYPECAST) {
				n->r1_data_defs.insert(curnode);
			}

			if (r2 == 1 && curop != DIF_OP_TYPECAST) {
				n->r2_data_defs.insert(curnode);
			}
		}

		clobbers = dt_clobbers_reg(instr, rd);

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (clobbers && opcode != DIF_OP_TYPECAST)
			return (1);

		if (clobbers && opcode == DIF_OP_TYPECAST)
			*seen_typecast = 1;
	}

	return (0);
}

static void
dt_compute_active_varregs(uint8_t *active_varregs, size_t n_varregs,
    dfg_node *n)
{
	dif_instr_t instr, varsrc_instr;
	uint8_t opcode;
	uint8_t r1, r2, rd;
	size_t i;

	instr = n->get_instruction();
	opcode = DIF_INSTR_OP(instr);

	/*
	 * Based on the opcode, we will now compute the new set of active
	 * registers in the current run of the inference for varsources.
	 */
	switch (opcode) {
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_SUB:
	case DIF_OP_ADD:
	case DIF_OP_MUL:
	case DIF_OP_SRA:
		/*
		 * If either of r1 and r2 is active, we will activate rd too, as
		 * this is probably some computation of an offset within a
		 * variable. However, if both are inactive, then we deactivate
		 * rd as well.
		 */
		r1 = DIF_INSTR_R1(instr);
		r2 = DIF_INSTR_R2(instr);
		rd = DIF_INSTR_RD(instr);

		assert(rd < DIF_DIR_NREGS + 2);
		assert(r1 < DIF_DIR_NREGS + 2);
		assert(r2 < DIF_DIR_NREGS + 2);


		if (active_varregs[r1] == 0 && active_varregs[r2] == 0)
			active_varregs[rd] = 0;

		if (active_varregs[rd] == 0 && active_varregs[r1] == 1)
			active_varregs[rd] = 1;

		if (active_varregs[rd] == 0 && active_varregs[r2] == 1)
			active_varregs[rd] = 1;
		break;

	case DIF_OP_MOV:
		/*
		 * For any one of these instructions, we will compute if
		 * r1 is already an active register. If so, we simply activate
		 * rd as well.
		 */
		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);
		assert(rd < DIF_DIR_NREGS + 2);
		assert(r1 < DIF_DIR_NREGS + 2);

		active_varregs[rd] = active_varregs[r1];
		break;

	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX:
	case DIF_OP_CMP:
	case DIF_OP_TST:
	case DIF_OP_BA:
	case DIF_OP_BE:
	case DIF_OP_BNE:
	case DIF_OP_BG:
	case DIF_OP_BGU:
	case DIF_OP_BGE:
	case DIF_OP_BGEU:
	case DIF_OP_BL:
	case DIF_OP_BLU:
	case DIF_OP_BLE:
	case DIF_OP_BLEU:
	case DIF_OP_NOP:
	case DIF_OP_SCMP:
	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
	case DIF_OP_POPTS:
		break;

	case DIF_OP_RET:
		/*
		 * On a ret instruction, all of the active registers are
		 * cleared. We are not longer actively looking to figure out
		 * which registers could be defining a variable, and therefore
		 * we don't want to keep track of them.
		 */
		for (i = 0; i < n_varregs; i++)
			active_varregs[i] = 0;

	default:
		rd = DIF_INSTR_RD(instr);
		assert(rd < DIF_DIR_NREGS + 2);

		active_varregs[rd] = 0;
	}
}

static void
update_active_varregs(uint8_t active_varregs[DIF_DIR_NREGS],
    dtrace_difo_t *_difo, basic_block *bb, dfg_list::iterator pos)
{
	dfg_node *curnode, *n;
	dif_instr_t instr;
	uint8_t opcode;
	uint16_t varid;
	int scope, kind;
	dtrace_difv_t *difv;
	uint8_t curnode_rd, rd, r1;

	assert(_difo != nullptr && bb != nullptr);

	curnode = pos->get();
	instr = curnode->get_instruction();
	opcode = DIF_INSTR_OP(instr);

	/*
	 * This is only really relevant for load instructions -- nothing else
	 * in DIF can define a register as "containing a variable" that we can
	 * infer statically -- so we don't allow it.
	 */
	if (opcode != DIF_OP_LDGS && opcode != DIF_OP_LDGA &&
	    opcode != DIF_OP_LDTS && opcode != DIF_OP_LDTA &&
	    opcode != DIF_OP_LDLS)
		return;

	varid = DIF_INSTR_VAR(instr);

	/*
	 * Annoying boilerplate to compute the kind and scope of the variable.
	 */
	if (opcode == DIF_OP_LDGS || opcode == DIF_OP_LDTS ||
	    opcode == DIF_OP_LDLS)
		kind = DIFV_KIND_SCALAR;
	else
		kind = DIFV_KIND_ARRAY;

	if (opcode == DIF_OP_LDGS || opcode == DIF_OP_LDGA)
		scope = DIFV_SCOPE_GLOBAL;
	else if (opcode == DIF_OP_LDTS || opcode == DIF_OP_LDTA)
		scope = DIFV_SCOPE_THREAD;
	else
		scope = DIFV_SCOPE_LOCAL;

	curnode_rd = DIF_INSTR_RD(instr);
	assert(curnode_rd < DIF_DIR_NREGS + 2);

	/*
	 * Activate the current node's destination register.
	 */
	active_varregs[curnode_rd] = 1;

	/*
	 * Go through all of the nodes in the current basic block
	 */
	for (; pos != dfg_nodes.end(); ++pos) {
		n = pos->get();
		instr = n->get_instruction();
		opcode = DIF_INSTR_OP(instr);

		if (n == curnode)
			continue;

		if (n->difo != _difo)
			continue;

		/*
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (curnode->uidx >= n->uidx)
			continue;

		if (n->uidx < bb->start || n->uidx > bb->end)
			continue;

		/*
		 * Compute which registers are being activated or deactivated
		 * with this node.
		 */
		dt_compute_active_varregs(active_varregs, DIF_DIR_NREGS, n);

		bool keep_going = false;
		for (auto i = 0; i < DIF_DIR_NREGS + 2; i++)
			if (active_varregs[i] == 1)
				keep_going = true;

		/*
		 * If there's no reason to keep going, that is to say that all
		 * the active registers have been clobbered, we simply return
		 * from the subroutine.
		 */
		if (!keep_going)
			return;

		if (opcode != DIF_OP_STB && opcode != DIF_OP_STH &&
		    opcode != DIF_OP_STW && opcode != DIF_OP_STX)
			continue;

		/*
		 * If we have STB/STH/STW/STX, we will get its r1 register and
		 * check if it's active. If so, we will add our varsource to the
		 * list.
		 */
		rd = DIF_INSTR_RD(instr);
		assert(rd < DIF_DIR_NREGS + 2);

		if (active_varregs[rd] == 0)
			continue;

		assert(scope == DIFV_SCOPE_GLOBAL ||
		    scope == DIFV_SCOPE_THREAD || scope == DIFV_SCOPE_LOCAL);
		assert(kind == DIFV_KIND_ARRAY || kind == DIFV_KIND_SCALAR);

		difv = dt_get_var_from_vec(varid, scope, kind);
		if (difv == nullptr)
			errx(EXIT_FAILURE,
			    "dt_get_var_from_vec(): failed to get DIF "
			    "variable from the list (%u, %d, %d)\n",
			    varid, scope, kind);

		n->var_sources.push_back(difv);
	}
}

static void
remove_basic_blocks(basic_block *bb,
    hashmap<size_t, basic_block *> &bb_map, vec<basic_block *> &bb_path)
{
	basic_block *parent_basic_block;
	int remove;

	/*
	 * Start by removing the current basic block from the path. Since
	 * this will always be the last element in bb_path, we just need to
	 * decrement bb_last and we can consider it to be out of bb_path.
	 */
	bb_map.erase(bb->idx);
	bb_path.pop_back();

	/*
	 * Find the parent that's in the path.
	 */
	parent_basic_block = nullptr;
	for (auto p : bb->parents) {
		if (bb_map.contains(p.first->idx)) {
			parent_basic_block = p.first;
			break;
		}
	}

	/*
	 * There's only one case when we won't have a parent. That case is when
	 * we are in the root node. In that case, we will simply assert a few
	 * things and break out of the function.
	 */
	assert((bb->parents.empty() && parent_basic_block == nullptr) ||
	    (!bb->parents.empty() && parent_basic_block != nullptr));

	if (parent_basic_block == nullptr) {
		assert(bb->start == 0);
		return;
	}

	remove = 1;
	for (auto child : parent_basic_block->children) {
		if (child.second == true) {
			remove = 0;
			break;
		}
	}

	if (remove)
		remove_basic_blocks(parent_basic_block, bb_map, bb_path);
}

static void
dt_update_nodes(dtrace_difo_t *difo, basic_block *bbp, dfg_node_data &data,
    dfg_list::iterator pos)
{
	bool redefined, var_redefined;
	uint8_t rd;
	uint16_t var;
	hashmap<size_t, basic_block *> bb_map;
	vec<basic_block *> bb_path;
	std::stack<basic_block *> bb_stack;
	size_t i;
	uint8_t active_varregs[DIF_DIR_NREGS + 2];
	int seen_typecast = 0;

	if (difo == nullptr || bbp == nullptr)
		return;

	memset(active_varregs, 0, sizeof(active_varregs));

	bb_stack.push(bbp);
	while (!bb_stack.empty()) {
		auto bb = bb_stack.top();
		assert(bb != nullptr);

		bb_stack.pop();

		redefined = false;
		var_redefined = false;

		bb_path.push_back(bb);
		bb_map[bb->idx] = bb;

		if (data.kind == DT_NKIND_REG) {
			if (!redefined)
				redefined = dt_update_nodes_bb_reg(difo, bb,
				    data.rd(), pos, &seen_typecast);
			if (!var_redefined) {
				update_active_varregs(active_varregs, difo, bb,
				    pos);
				var_redefined = true;
				for (i = 0; i < DIF_DIR_NREGS + 2; i++)
					if (active_varregs[i] == 1)
						var_redefined = false;
			}
		} else if (data.kind == DT_NKIND_VAR)
			redefined = dt_update_nodes_bb_var(difo, bb, data,
			    pos);
		else if (data.kind == DT_NKIND_STACK)
			redefined = dt_update_nodes_bb_stack(bb_path, difo, bb,
			    pos);
		else
			return;

		if (redefined || bb->children.empty())
			remove_basic_blocks(bb, bb_map, bb_path);

		if ((data.kind == DT_NKIND_REG && var_redefined == false) ||
		    !redefined) {
			for (auto child : bb->children) {
				bb_stack.push(child.first);
				/*
				 * This is a little more subtle than it looks.
				 * dtbe_tovisit here is not per basic-block.
				 * It is in fact per individual child of each
				 * basic block -- which differs for different
				 * basic blocks. This ensures that we have a
				 * way to say "have we visited the children
				 * of *this particular basic block*" rather than
				 * "have we visited this basic block".
				 */
				child.second = false;
			}
		}
	}
}

static void
dt_update_dfg(dtrace_difo_t *difo, dfg_node *n,
    dfg_list::iterator pos)
{

	dt_update_nodes(difo, n->bb, n->node_data, pos);
}

static basic_block *
dt_node_find_bb(basic_block *root, uint_t ins_idx)
{
	std::stack<basic_block *> bb_stack;
	uset<size_t> visited;

	if (root == nullptr)
		return (nullptr);

	bb_stack.push(root);
	while (!bb_stack.empty()) {
		auto bb = bb_stack.top();
		assert(bb != nullptr);

		bb_stack.pop();
		if (!visited.contains(bb->idx)) {
			visited.insert(bb->idx);
			if (bb->start <= ins_idx && bb->end >= ins_idx)
				return (bb);
		}

		for (auto child : bb->children) {
			assert(child.first != nullptr);

			if (!visited.contains(child.first->idx))
				bb_stack.push(child.first);
		}
	}

	return (nullptr);
}

/*
 * We assume that both dtp and difo are not nullptr.
 */
int
dt_compute_dfg(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_ecbdesc_t *edp, dtrace_difo_t *difo)
{
	dfg_list::iterator fst;
	dif_instr_t instr = 0;

	/*
	 * Passing a nullptr difo makes no sense.
	 */
	if (difo == nullptr)
		return (EDT_DIFINVAL);

	/*
	 * A DIFO without instructions makes no sense.
	 */
	if (difo->dtdo_buf == nullptr)
		return (EDT_DIFINVAL);

	/*
	 * If we don't have a table, length MUST be 0.
	 */
	if (difo->dtdo_inttab == nullptr && difo->dtdo_intlen != 0)
		return (EDT_DIFINVAL);
	if (difo->dtdo_strtab == nullptr && difo->dtdo_strlen != 0)
		return (EDT_DIFINVAL);
	if (difo->dtdo_vartab == nullptr && difo->dtdo_varlen != 0)
		return (EDT_DIFINVAL);
	if (difo->dtdo_symtab == nullptr && difo->dtdo_symlen != 0)
		return (EDT_DIFINVAL);

	if (difo->dtdo_len == 0)
		return (EDT_DIFINVAL);

	/*
	 * If the symbol length is 0 and the symbol table is 0, we don't
	 * have any relocations to apply. In this case, we just return that
	 * no error occurred and leave the DIFO as it is.
	 */
	if (difo->dtdo_symtab == nullptr)
		return (0);

	/*
	 * Compute the basic blocks, CFG and prepare the data flow node vector.
	 */
	dt_compute_bb(difo);
	dt_compute_cfg(difo);
	fst = dfg_nodes.end();

	/*
	 * First pass over the instructions. We build up all of the IFG nodes
	 * that we are going to need.
	 */
	for (auto i = 0; i < difo->dtdo_len; i++) {
		auto node_basic_block = dt_node_find_bb(
		    static_cast<basic_block *>(difo->dtdo_bb), i);
		assert(node_basic_block != nullptr);
		dfg_nodes.push_back(std::make_unique<dfg_node>(dtp, pgp, edp,
		    difo, node_basic_block, i));
		if (i == 0) {
			fst = std::prev(dfg_nodes.end());
		}
	}

	/*
	 * Second pass over all the instructions, but this time we actually
	 * compute the IFG.
	 */
	for (auto it = fst; it != dfg_nodes.end(); ++it) {
		auto n = it->get();
		if (n == r0node)
			continue;
		instr = n->get_instruction();

		get_node_data(instr, n->node_data);
		dt_update_dfg(difo, n, it);
	}

	return (0);
}

dfg_node *
dfg_node::find_child(dfg_node *find) {
	if (this == find)
		return (this);

	if (auto f = this->r1_data_defs.find(find);
	    f != this->r1_data_defs.end())
		return (*f);

	if (auto f = this->r2_data_defs.find(find);
	    f != this->r2_data_defs.end())
		return (*f);

	return (nullptr);
}

}