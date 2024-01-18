/*-
 * Copyright (c) 2020 Domagoj Stolfa
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
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/dtrace.h>

#include <assert.h>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_impl.h>
#include <dt_linker_subr.hh>
#include <dt_module.h>
#include <dt_program.h>
#include <dt_typefile.hh>
#include <dtrace.h>
#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

dtrace_difv_t *
dt_get_variable(dtrace_difo_t *difo, uint16_t varid, int scope, int kind)
{
	for (auto i = 0; i < difo->dtdo_varlen; i++) {
		auto var = &difo->dtdo_vartab[i];

		if (var->dtdv_scope == scope && var->dtdv_kind == kind &&
		    var->dtdv_id == varid)
			return (var);
	}

	return (nullptr);
}

namespace dtrace {

int
dt_subr_clobbers(uint16_t subr)
{
	switch (subr) {
	case DIF_SUBR_BCOPY:
	case DIF_SUBR_COPYOUT:
	case DIF_SUBR_COPYOUTSTR:
	case DIF_SUBR_COPYINTO:
		return (0);

	default:
		return (1);
	}
}

int
dt_clobbers_reg(dif_instr_t instr, uint8_t r)
{
	uint8_t opcode;
	uint8_t rd;
	uint16_t subr;

	opcode = DIF_INSTR_OP(instr);

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
		rd = DIF_INSTR_RD(instr);
		return (r == rd);

	case DIF_OP_CALL:
		rd = DIF_INSTR_RD(instr);
		subr = DIF_INSTR_SUBR(instr);

		if (dt_subr_clobbers(subr))
			return (r == rd);
		return (0);
	}

	return (0);
}

int
dt_var_is_builtin(uint16_t var)
{
	if (var == DIF_VAR_ARGS || var == DIF_VAR_REGS || var == DIF_VAR_UREGS)
		return (1);

	if (var >= DIF_VAR_CURTHREAD && var <= DIF_VAR_MAX)
		return (1);

	return (0);
}

int
dt_clobbers_var(dif_instr_t instr, dfg_node_data &data)
{
	uint8_t opcode;
	uint16_t v;
	uint8_t scope, varkind;

	scope = data.scope();
	varkind = data.varkind();

	if (varkind == DIFV_KIND_ARRAY)
		return (0);

	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_STGS:
		if (scope != DIFV_SCOPE_GLOBAL)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (data.var() == v)
			return (1);
		break;

	case DIF_OP_STLS:
		if (scope != DIFV_SCOPE_LOCAL)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (data.var() == v)
			return (1);
		break;

	case DIF_OP_STTS:
		if (scope != DIFV_SCOPE_THREAD)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (data.var() == v)
			return (1);
		break;
	}

	return (0);
}

dtrace_difv_t *
dt_get_var_from_vec(uint16_t varid, int scope, int kind)
{
	for (auto &v : var_vector) {
		if (v->dtdv_scope == scope && v->dtdv_kind == kind &&
		    v->dtdv_id == varid)
			return (v.get());
	}

	return (nullptr);
}

void
dt_get_varinfo(dif_instr_t instr, uint16_t *varid, int *scope, int *kind)
{
	uint8_t opcode;

	opcode = DIF_INSTR_OP(instr);
	switch (opcode) {
	case DIF_OP_STGS:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_GLOBAL;
		*kind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STTS:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_THREAD;
		*kind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STLS:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_LOCAL;
		*kind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STGAA:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_GLOBAL;
		*kind = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTAA:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_THREAD;
		*kind = DIFV_KIND_ARRAY;
		break;

	default:
		*varid = 0;
		*scope = -1;
		*kind = -1;
		break;
	}
}

void
dt_insert_var_by_tup(dtrace_hdl_t *dtp, dtrace_difo_t *difo, uint16_t varid,
    uint8_t scope, uint8_t kind)
{
	dtrace_difv_t *var = nullptr;
	dtrace_difv_t *difv;
	ctf_file_t *d_ctfp;
	dt_module_t *d_mod;

	/*
	 * Search through the existing variable list looking for
	 * the variable being currently defined. If we find it,
	 * we will simply break out of the loop and move onto
	 * the next instruction.
	 */
	for (auto &v : var_vector) {
		if (v->dtdv_scope == scope && v->dtdv_kind == kind &&
		    v->dtdv_id == varid) {
			var = v.get();
			break;
		}
	}

	if (var && var->dtdv_ctfid != CTF_ERR)
		return;

	difv = dt_get_variable(difo, varid, scope, kind);
	if (difv == nullptr)
		errx(EXIT_FAILURE, "%s(): failed to find variable (%u, %d, %d)",
		    __func__, varid, scope, kind);

	/*
	 * Allocate a new variable to be put into our list and
	 * copy the contents of the variable in the DIFO table
	 * into the newly allocated region.
	 */
	if (var == nullptr) {
		var_vector.push_back(std::make_unique<dtrace_difv_t>());
		var = var_vector.back().get();
		if (var == nullptr)
			errx(EXIT_FAILURE, "failed to allocate a new variable");
		memset(var, 0, sizeof(dtrace_difv_t));
		var->dtdv_ctfid = CTF_ERR;
	}

	assert(var->dtdv_ctfid == CTF_ERR);
	memcpy(var, difv, sizeof(dtrace_difv_t));

	d_mod = dt_module_lookup_by_name(dtp, "D");
	assert(d_mod != NULL);
	d_ctfp = dt_module_getctf(dtp, d_mod);
	assert(d_ctfp != NULL);

	if (difv->dtdv_ctfp != d_ctfp) {
		var->dtdv_ctfid = CTF_ERR;
		var->dtdv_sym = NULL;
		var->dtdv_type.dtdt_kind =
		    DIF_TYPE_BOTTOM; /* can be anything */
		var->dtdv_type.dtdt_size = 0;
		var->dtdv_stack = NULL;
		var->dtdv_tf = NULL;
		var->dtdv_storedtype = difv->dtdv_storedtype;
	} else {
		var->dtdv_ctfid = difv->dtdv_ctfid;
		var->dtdv_sym = NULL;
		var->dtdv_type = difv->dtdv_type;
		var->dtdv_stack = NULL;
		var->dtdv_tf = dt_typefile_D();
		var->dtdv_storedtype = difv->dtdv_storedtype;
	}
}

int
dt_var_uninitialized(dtrace_difv_t *difv)
{

	return (difv->dtdv_ctfid == CTF_ERR && difv->dtdv_tf == NULL &&
	    difv->dtdv_sym == NULL);
}

void
dt_insert_var_by_difv(dtrace_hdl_t *dtp, dtrace_difv_t *difv)
{
	dtrace_difv_t *var = nullptr;
	ctf_file_t *d_ctfp;
	dt_module_t *d_mod;

	/*
	 * Search through the existing variable list looking for
	 * the variable being currently defined. If we find it,
	 * we will simply break out of the loop and move onto
	 * the next instruction.
	 */
	for (auto &v : var_vector) {
		if (v->dtdv_scope == difv->dtdv_scope &&
		    v->dtdv_kind == difv->dtdv_kind &&
		    v->dtdv_id == difv->dtdv_id) {
			var = v.get();
			break;
		}
	}

	if (var && var->dtdv_ctfid != CTF_ERR)
		return;

	/*
	 * Allocate a new variable to be put into our list and
	 * copy the contents of the variable in the DIFO table
	 * into the newly allocated region.
	 */
	if (var == nullptr) {
		var_vector.push_back(std::make_unique<dtrace_difv_t>());
		var = var_vector.back().get();
		if (var == nullptr)
			errx(EXIT_FAILURE, "failed to allocate a new variable");
		memset(var, 0, sizeof(dtrace_difv_t));
		var->dtdv_ctfid = CTF_ERR;
	}


	assert(var->dtdv_ctfid == CTF_ERR);
	memcpy(var, difv, sizeof(dtrace_difv_t));

	d_mod = dt_module_lookup_by_name(dtp, "D");
	assert(d_mod != NULL);
	d_ctfp = dt_module_getctf(dtp, d_mod);
	assert(d_ctfp != NULL);

	if (difv->dtdv_ctfp != d_ctfp) {
		var->dtdv_ctfid = CTF_ERR;
		var->dtdv_sym = NULL;
		var->dtdv_type.dtdt_kind = DIF_TYPE_BOTTOM;
		var->dtdv_type.dtdt_size = 0;
		var->dtdv_stack = NULL;
		var->dtdv_tf = NULL;
		var->dtdv_storedtype = difv->dtdv_type;
	} else {
		var->dtdv_ctfid = difv->dtdv_ctfid;
		var->dtdv_sym = NULL;
		var->dtdv_type = difv->dtdv_type;
		var->dtdv_stack = NULL;
		var->dtdv_tf = dt_typefile_D();
		var->dtdv_storedtype = difv->dtdv_type;
	}
}

void
dt_populate_varlist(dtrace_hdl_t *dtp, dtrace_difo_t *difo)
{
	dtrace_difv_t *difv;
	size_t i;
	uint8_t opcode;
	dif_instr_t instr;
	uint16_t varid;

	for (i = 0; i < difo->dtdo_varlen; i++) {
		difv = &difo->dtdo_vartab[i];
		dt_insert_var_by_difv(dtp, difv);
	}

	for (i = 0; i < difo->dtdo_len; i++) {
		instr = difo->dtdo_buf[i];
		opcode = DIF_INSTR_OP(instr);

		switch (opcode) {
		case DIF_OP_STGS:
		case DIF_OP_LDGS:
			varid = DIF_INSTR_VAR(instr);
			if (!dt_var_is_builtin(varid))
				dt_insert_var_by_tup(dtp, difo, varid,
				    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);
			break;

		case DIF_OP_LDLS:
		case DIF_OP_STLS:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var_by_tup(dtp, difo, varid, DIFV_SCOPE_LOCAL,
			    DIFV_KIND_SCALAR);
			break;

		case DIF_OP_LDTS:
		case DIF_OP_STTS:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var_by_tup(dtp, difo, varid,
			    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
			break;

		case DIF_OP_LDGAA:
		case DIF_OP_STGAA:
			varid = DIF_INSTR_VAR(instr);
			if (!dt_var_is_builtin(varid))
				dt_insert_var_by_tup(dtp, difo, varid,
				    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
			break;

		case DIF_OP_LDTAA:
		case DIF_OP_STTAA:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var_by_tup(dtp, difo, varid,
			    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
			break;

		default:
			break;
		}
	}
}

ssize_t
dt_get_stack(vec<basic_block *> &bb_path, dfg_node *n)
{
	assert(!bb_path.empty());

	for (ssize_t i = 0; i < n->stacks.size(); i++) {
		auto &s = n->stacks[i];
		if (s.identifier == bb_path) {
			return (i);
		}
	}

	n->stacks.push_back(stackdata(bb_path));
	return (n->stacks.size() - 1);
}

}