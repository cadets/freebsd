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
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/linker.h>

#include <sys/dtrace.h>

#include <dtrace.h>

#include <dt_impl.h>
#include <dt_program.h>

#include <dt_dfg.hh>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_linker_subr.hh>
#include <dt_typefile.hh>
#include <dt_typing.hh>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>

#ifndef illumos
#include <sys/sysctl.h>
#endif

char t_mtx[MAXPATHLEN];
char t_rw[MAXPATHLEN];
char t_sx[MAXPATHLEN];
char t_thread[MAXPATHLEN];

namespace dtrace {

template <typename T> using vec = std::vector<T>;
template <typename T> using uptr = std::unique_ptr<T>;

dfg_list dfg_nodes;
vec<uptr<basic_block>> basic_blocks;
vec<uptr<dtrace_difv_t>> var_vector;
dfg_node *r0node = nullptr;

typedef struct dtrace_ecbdesclist {
	dt_list_t next;
	dtrace_ecbdesc_t *ecbdesc;
} dtrace_ecbdesclist_t;

static void
patch_usetxs(dtrace_hdl_t *dtp, dfg_node *n)
{
	uint8_t rd, opcode;
	dif_instr_t instr;
	int index;
	uint16_t offset;

	if (n == nullptr)
		return;

	if (n->difo == nullptr)
		return;

	if (n->mip == nullptr)
		return;

	offset = n->mip->ctm_offset / 8 /* bytes */;

	for (auto node : n->usetx_defs) {
		if (node->relocated)
			continue;

		instr = node->get_instruction();
		opcode = DIF_INSTR_OP(instr);
		if (opcode != DIF_OP_USETX)
			errx(EXIT_FAILURE, "opcode (%d) is not usetx", opcode);

		rd = DIF_INSTR_RD(instr);

		if (n->difo->dtdo_inthash == nullptr) {
			n->difo->dtdo_inthash = dt_inttab_create(dtp);

			if (n->difo->dtdo_inthash == nullptr)
				errx(EXIT_FAILURE,
				    "failed "
				    "to allocate inttab");
		}

		if ((index = dt_inttab_insert(n->difo->dtdo_inthash, offset,
		    0)) == -1)
			errx(EXIT_FAILURE, "failed to insert %u into inttab",
			    offset);

		node->difo_buf()[node->uidx] = DIF_INSTR_SETX(index, rd);
		node->relocated = true;
	}
}

static void
dt_prepare_typestrings(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	char __kernel[] = "kernel`";
	size_t __kernel_len = strlen(__kernel);

	if (strncmp(mtx_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "mtx_str does not start with \"kernel`\" (%s)", mtx_str);

	if (strncmp(rw_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "rw_str does not start with \"kernel`\" (%s)", rw_str);

	if (strncmp(sx_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "sx_str does not start with \"kernel`\" (%s)", sx_str);

	memcpy(t_mtx, mtx_str + __kernel_len, MAXPATHLEN - __kernel_len);
	memcpy(t_rw, rw_str + __kernel_len, MAXPATHLEN - __kernel_len);
	memcpy(t_sx, sx_str + __kernel_len, MAXPATHLEN - __kernel_len);
	memcpy(t_thread, thread_str, MAXPATHLEN);
}

static void
relocate_uloadadd(dtrace_hdl_t *dtp, dfg_node *node)
{
	size_t size, kind;
	ctf_id_t ctfid;
	uint8_t rd, r1;
	uint8_t opcode, new_op;
	ctf_encoding_t encoding;
	dif_instr_t instr, new_instr;

	instr = node->get_instruction();
	opcode = DIF_INSTR_OP(instr);

	if (opcode == DIF_OP_ADD) {
		goto usetx_relo;
	}

	ctfid = node->tf->resolve(node->mip->ctm_type);
	size = node->tf->get_size(ctfid);
	kind = node->tf->get_kind(ctfid);


	/*
	 * NOTE: We support loading of CTF_K_ARRAY due to it
	 * just being a pointer, really.
	 */
	if (kind != CTF_K_INTEGER && kind != CTF_K_POINTER &&
	    kind != CTF_K_ARRAY)
		errx(EXIT_FAILURE, "a load of kind %zu is unsupported in DIF.",
		    kind);

	if (kind == CTF_K_POINTER || kind == CTF_K_ARRAY) {
		new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX : DIF_OP_ULDX;
		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);

		new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
	} else {
		if (node->tf->get_encoding(ctfid, &encoding) != 0)
			errx(EXIT_FAILURE, "failed to get encoding for %ld",
			    ctfid);

		if (encoding.cte_format & CTF_INT_SIGNED) {
			if (size == 1)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSB :
				    DIF_OP_ULDSB;
			else if (size == 2)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSH :
				    DIF_OP_ULDSH;
			else if (size == 4)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSW :
				    DIF_OP_ULDSW;
			else if (size == 8)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX :
				    DIF_OP_ULDX;
			else
				errx(
				    EXIT_FAILURE, "unsupported size %zu", size);
		} else {
			if (size == 1)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUB :
				    DIF_OP_ULDUB;
			else if (size == 2)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUH :
				    DIF_OP_ULDUH;
			else if (size == 4)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUW :
				    DIF_OP_ULDUW;
			else if (size == 8)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX :
				    DIF_OP_ULDX;
			else
				errx(
				    EXIT_FAILURE, "unsupported size %zu", size);
		}

		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);

		new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
	}

usetx_relo:
	ctf_membinfo_t *mip = nullptr;

	if (node->mip == nullptr) {
		if (node->sym == nullptr) {
			node->relocated = true;
			return;
		}

		mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
		assert(mip != nullptr);

		memset(mip, 0, sizeof(*mip));
		auto type = node->tf->get_reference(node->ctfid);
		if (node->tf->get_membinfo(type, node->sym, mip) == 0) {
			dt_set_progerr(node->dtp, node->program,
			    "%s(%p[%zu]): failed to get mip: %s.%s: %s\n",
			    __func__, node->difo, node->uidx,
			    node->tf->get_typename(node->ctfid)
				.value_or("UNKNOWN")
				.c_str(),
			    node->sym, node->tf->get_errmsg());
		}

		node->mip = mip;
	}

	patch_usetxs(dtp, node);

	if (opcode != DIF_OP_ADD)
		node->difo_buf()[node->uidx] = new_instr;
	node->relocated = true;
}

static void
relocate_retpush(dtrace_hdl_t *dtp, dfg_node *node,
    dtrace_actkind_t actkind, dtrace_actdesc_t *ad,
    dtrace_diftype_t *orig_rtype)
{

	/*
	 * If this instruction does not come from a usetx,
	 * we don't really have to do anything with it.
	 */
	if (node->mip == nullptr)
		return;

	patch_usetxs(dtp, node);
}

static void
relocate_push(dtrace_hdl_t *dtp, dfg_node *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *orig_rtype)
{

	relocate_retpush(dtp, node, actkind, ad, orig_rtype);
}

static void
ret_cleanup(dfg_node *node, dtrace_diftype_t *rtype)
{
	dif_instr_t instr;
	uint8_t opcode;

	/*
	 * We only need to clean up things if we return by reference
	 * currently.
	 */
	if ((rtype->dtdt_flags & DIF_TF_BYREF) == 0 &&
	    (rtype->dtdt_flags & DIF_TF_BYUREF) == 0)
		return;

	for (auto n : node->r1_defs) {
		instr = n->get_instruction();
		opcode = DIF_INSTR_OP(instr);

		switch (opcode) {
		case DIF_OP_ULOAD:
		case DIF_OP_UULOAD:
			break;

		case DIF_OP_LDUB:
		case DIF_OP_LDSB:
		case DIF_OP_LDUH:
		case DIF_OP_LDSH:
		case DIF_OP_LDUW:
		case DIF_OP_LDSW:
		case DIF_OP_LDX:
			n->difo_buf()[n->uidx] = DIF_INSTR_NOP;
			break;
		}
	}
}

static void
relocate_ret(dtrace_hdl_t *dtp, dfg_node *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *orig_rtype)
{
	dtrace_diftype_t *rtype;
	dtrace_difo_t *difo;
	dtrace_prog_t *pgp;
	ctf_id_t return_ctfid;
	int ctf_kind;

	/*
	 * In case of a RET, we first patch up the DIFO with the correct return
	 * type and size.
	 */
	difo = node->difo;
	rtype = &difo->dtdo_rtype;

	rtype->dtdt_kind = node->d_type;
	if (node->d_type == DIF_TYPE_CTF)
		rtype->dtdt_ckind = node->ctfid;
	else if (node->d_type == DIF_TYPE_STRING)
		rtype->dtdt_ckind = DT_STR_TYPE(dtp);
	else if (node->d_type == DIF_TYPE_BOTTOM)
		/*
		 * If we have a bottom type, we really
		 * don't care which CTF type the host
		 * wants here. It can be patched in
		 * later on demand.
		 */
		rtype->dtdt_ckind = CTF_BOTTOM_TYPE;
	else
		errx(EXIT_FAILURE,
		    "unexpected node->din_type (%x) at location %zu",
		    node->d_type, node->uidx);

	assert(actkind != DTRACEACT_NONE);
	if (actkind != DTRACEACT_DIFEXPR)
		assert(ad != nullptr);

	switch (actkind) {
	case DTRACEACT_EXIT:
		*rtype = dt_int_rtype;
		rtype->dtdt_size = sizeof(int);
		break;

	case DTRACEACT_PRINTA:
	case DTRACEACT_PRINTM:
	case DTRACEACT_TRACEMEM:
	case DTRACEACT_TRACEMEM_DYNSIZE:
		break;

	case DTRACEAGG_QUANTIZE:
	case DTRACEAGG_LQUANTIZE:
	case DTRACEAGG_LLQUANTIZE:
		break;

	case DTRACEACT_PRINTF:
	case DTRACEACT_DIFEXPR:
		if (ad && ad->dtad_return == 0) {
			*rtype = dt_void_rtype;
			break;
		}

		/*
		 * Fall through to the default case.
		 */
	default:
		if (node->mip == nullptr && rtype->dtdt_kind == DIF_TYPE_CTF) {
			ctf_kind = node->tf->get_kind(node->ctfid);

			/*
			 * XXX(dstolfa, important): Is this a sensible thing to
			 * be doing for all guests? We claim to know on the host
			 * whether or not we need to dereference something --
			 * but is that actually true? Need to think about this a
			 * bit more. On the guest, we lack the information about
			 * what takes a dereferenced value in, but on the host
			 * we lack type information.
			 */
			rtype->dtdt_flags = orig_rtype->dtdt_flags;

			if (ctf_kind == CTF_K_ARRAY) {
				rtype->dtdt_flags |= DIF_TF_BYREF;
			}

			ret_cleanup(node, rtype);

			if (rtype->dtdt_flags & DIF_TF_BYREF) {
				return_ctfid = node->tf->get_reference(
				    node->ctfid);
				/*
				 * FIXME:. This is very much a heuristic. This
				 * can probably be done better.
				 */
				return_ctfid = return_ctfid == CTF_ERR ?
				    node->ctfid :
				    return_ctfid;
				rtype->dtdt_size = node->tf->get_size(
				    return_ctfid);
			} else {
				rtype->dtdt_size = node->tf->get_size(
				    node->ctfid);
			}
		} else if (rtype->dtdt_kind == DIF_TYPE_BOTTOM) {
			/*
			 * We don't care what the size is, we just need to set
			 * the correct flags.
			 */
			rtype->dtdt_flags = orig_rtype->dtdt_flags;
		} else {
			rtype->dtdt_flags |= DIF_TF_BYREF;
		}

		break;
	}
	/*
	 * Safety guard
	 */
	if (node->d_type == DIF_TYPE_STRING) {
		rtype->dtdt_flags |= DIF_TF_BYREF;
		rtype->dtdt_ckind = CTF_ERR;
	}

	relocate_retpush(dtp, node, actkind, ad, orig_rtype);
}

static void
patch_setxs(node_set *setx_defs1, node_set *setx_defs2)
{
	node_set::iterator it1, it2;
	for (it1 = setx_defs1->begin(), it2 = setx_defs2->begin();
	     it1 != setx_defs1->end() && it2 != setx_defs2->end();
	     ++it1, ++it2) {
		auto sd1 = *it1;
		auto sd2 = *it2;

		sd1->difo_buf()[sd1->uidx] = DIF_INSTR_NOP;
		sd2->difo_buf()[sd2->uidx] = DIF_INSTR_NOP;
	}
}

static bool
check_setxs(node_set *setx_defs1, node_set *setx_defs2)
{
	dfg_node *sd1, *sd2;
	dif_instr_t instr1, instr2;
	uint8_t op1, op2;
	node_set::iterator it1, it2;

	for (it1 = setx_defs1->begin(), it2 = setx_defs2->begin();
	     it1 != setx_defs1->end() && it2 != setx_defs2->end();
	     ++it1, ++it2) {
		sd1 = *it1;
		sd2 = *it2;

		instr1 = sd1->get_instruction();
		instr2 = sd2->get_instruction();

		op1 = DIF_INSTR_OP(instr1);
		op2 = DIF_INSTR_OP(instr2);

		/*
		 * This is really the only thing we need to check here.
		 */
		if (op1 != DIF_OP_SETX || instr1 != instr2)
			return (false);
	}

	return (true);
}

static void
relocate_dfg_node(dfg_node *node, dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_actkind_t actkind, dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_diftype_t *orig_rtype)
{
	dif_instr_t instr;
	uint8_t opcode;

	if (node->difo != difo)
		return;

	instr = node->get_instruction();
	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_RET:
		relocate_ret(dtp, node, actkind, ad, orig_rtype);
		break;

	case DIF_OP_PUSHTR:
		relocate_push(dtp, node, actkind, ad, orig_rtype);
		break;

	case DIF_OP_PUSHTV: {
		/*
		 * Patch up the type we're pushing on the stack.
		 */
		dif_instr_t newinstr;
		uint8_t rs, rv;

		rs = DIF_INSTR_RS(instr);
		rv = DIF_INSTR_R2(instr);

		newinstr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
		    node->d_type, rv, rs);
		node->difo_buf()[node->uidx] = newinstr;
		break;
	}

	case DIF_OP_ADD:
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
		relocate_uloadadd(dtp, node);
		break;

	case DIF_OP_TYPECAST: {
		dif_instr_t idef1, idef2;
		uint8_t opdef1, opdef2;
		uint8_t r11, r12, r21, r22, currd, rd;
		node_set *setx_defs1, *setx_defs2, *defs;
		std::string symname;
		uint16_t sym;
		size_t l;

		/*
		 * For typecast, we simply turn it into a nop. We only
		 * ever use typecast for type inference and can't
		 * actually execute it as an instruction. We will
		 * collapse the nops later.
		 */
		node->difo_buf()[node->uidx] = DIF_INSTR_NOP;

		if (node->uidx < 2)
			goto end;

		patch_usetxs(dtp, node);
		sym = DIF_INSTR_SYMBOL(instr);
		currd = DIF_INSTR_RD(instr);

		if (sym >= difo->dtdo_symlen)
			dt_set_progerr(dtp, pgp,
			    "%s(): sym (%u) >= symlen (%zu)\n", __func__, sym,
			    difo->dtdo_symlen);

		symname = std::string(difo->dtdo_symtab + sym);
		if (symname == "uintptr_t")
			goto end;

		/*
		 * Now we need to check if we have an sll followed by an sra as
		 * the previous two instructions. This can happen in the case
		 * sign extension is needed -- however we don't actually want to
		 * do this for an uintptr_t.
		 */
		for (auto ndef1 : node->r1_defs) {
			idef1 = ndef1->get_instruction();
			opdef1 = DIF_INSTR_OP(idef1);

			if (opdef1 != DIF_OP_SRA)
				continue;

			r11 = DIF_INSTR_R1(idef1);
			r21 = DIF_INSTR_R2(idef1);

			/*
			 * Figure out which register we need to look up the
			 * definitions for.
			 */
			defs = nullptr;
			setx_defs1 = nullptr;

			if (r11 == currd) {
				defs = &ndef1->r1_defs;
				setx_defs1 = &ndef1->r2_defs;
			}

			if (r21 == currd) {
				/*
				 * Assert that we don't have a sra %r1, %r1, %r1
				 * as that would be extremely weird.
				 */
				assert(defs == nullptr);
				assert(setx_defs1 == nullptr);
				defs = &ndef1->r2_defs;
				setx_defs1 = &ndef1->r1_defs;
			}

			if (defs == nullptr)
				continue;

			for (auto ndef2 : *defs) {
				idef2 = ndef2->get_instruction();
				opdef2 = DIF_INSTR_OP(idef2);

				if (opdef2 != DIF_OP_SLL)
					continue;

				r12 = DIF_INSTR_R1(idef2);
				r22 = DIF_INSTR_R2(idef2);

				rd = DIF_INSTR_RD(idef2);

				setx_defs2 = nullptr;
				if (r12 == rd)
					setx_defs2 = &ndef2->r2_defs;

				if (r22 == rd)
					setx_defs2 = &ndef2->r1_defs;

				if (setx_defs2 == nullptr)
					continue;

				if (!check_setxs(setx_defs1, setx_defs2))
					continue;

				ndef2->difo_buf()[ndef2->uidx] = DIF_INSTR_NOP;
				ndef1->difo_buf()[ndef1->uidx] = DIF_INSTR_NOP;

				patch_setxs(setx_defs1, setx_defs2);
			}
		}

end:
		node->relocated = true;
		break;
	}

	default:
		break;
	}
}

static int
dt_prog_relocate(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_actkind_t actkind, dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_diftype_t *orig_rtype)
{
	int i, index;

	if (difo->dtdo_inttab != nullptr) {
		assert(difo->dtdo_intlen != 0);
		assert(difo->dtdo_inthash == nullptr);

		difo->dtdo_inthash = dt_inttab_create(dtp);
		if (difo->dtdo_inthash == nullptr)
			errx(EXIT_FAILURE, "failed to allocate inthash");

		for (i = 0; i < difo->dtdo_intlen; i++) {
			if ((index = dt_inttab_insert(difo->dtdo_inthash,
			    difo->dtdo_inttab[i], 0)) != i)
				errx(EXIT_FAILURE,
				    "failed to insert %" PRIu64 ", got %d (!= %d)\n",
				    difo->dtdo_inttab[i], index, i);
		}
	}

	for (auto &n : dfg_nodes) {
		if (n.get() == r0node)
			continue;
		relocate_dfg_node(n.get(), dtp, pgp, actkind, ad, difo,
		    orig_rtype);
	}

	return (0);
}

static void
dt_update_usetx_bb(dtrace_difo_t *difo, basic_block *bb, dfg_node *n)
{
	dif_instr_t instr;
	uint8_t opcode;

	if (n->sym == nullptr)
		errx(EXIT_FAILURE, "usetx din_sym should not be nullptr");

	for (auto &node : dfg_nodes) {
		if (node.get() == r0node)
			continue;

		instr = node->get_instruction();
		opcode = DIF_INSTR_OP(instr);

		if (node.get() == n)
			continue;

		if (node->difo != difo)
			continue;

		if (n->uidx >= node->uidx)
			continue;

		if (node->uidx < bb->start || node->uidx > bb->end)
			continue;

		if (opcode == DIF_OP_ULOAD    ||
		    opcode == DIF_OP_UULOAD   ||
		    opcode == DIF_OP_RET      ||
		    opcode == DIF_OP_PUSHTR   ||
		    opcode == DIF_OP_ADD      ||
		    opcode == DIF_OP_TYPECAST) {
			auto usetx_node = node->find_child(n);
			if (usetx_node != n)
				continue;

			node->usetx_defs.insert(n);
		}
	}
}

static void
dt_update_usetxs(dtrace_difo_t *difo, basic_block *bb, dfg_node *n)
{
	dt_update_usetx_bb(difo, bb, n);

	for (auto child : bb->children) {
		dt_update_usetxs(difo, child.first, n);
	}
}

static void
dt_prog_infer_usetxs(dtrace_difo_t *difo)
{
	basic_block *bb = static_cast<basic_block *>(difo->dtdo_bb);

	for (auto it = dfg_nodes.rbegin(); it != dfg_nodes.rend(); ++it) {
		auto n = it->get();
		assert(n != nullptr);

		if (n->sym == nullptr)
			continue;

		if (n->difo != difo)
			continue;

		dif_instr_t instr = n->get_instruction();
		uint8_t opcode = DIF_INSTR_OP(instr);

		if (opcode != DIF_OP_USETX)
			continue;

		dt_update_usetxs(difo, bb, n);
	}
}

static void
dt_prog_assemble(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_difo_t *difo,
    dtrace_diftype_t **biggest_type)
{
	size_t inthash_size;
	uint64_t *otab;
	size_t i;
	dtrace_difv_t *var, *vlvar;
	uint32_t id;
	uint8_t scope;

	var = vlvar = nullptr;
	i = 0;
	otab = nullptr;
	inthash_size = 0;

	if (difo->dtdo_inthash != nullptr) {
		inthash_size = dt_inttab_size(difo->dtdo_inthash);
		if (inthash_size == 0) {
			fprintf(stderr, "inthash_size is 0\n");
			return;
		}

		otab = difo->dtdo_inttab;
		difo->dtdo_inttab = (uint64_t *)dt_alloc(dtp,
		    sizeof(uint64_t) * inthash_size);
		if (difo->dtdo_inttab == nullptr)
			errx(EXIT_FAILURE, "failed to malloc inttab");

		memset(difo->dtdo_inttab, 0, sizeof(uint64_t) * inthash_size);
		free(otab);

		dt_inttab_write(difo->dtdo_inthash,
		    difo->dtdo_inttab);

		difo->dtdo_intlen = inthash_size;
	}

	/*
	 * By this time we should have any variable being used in this
	 * DIFO inside the varlist because the only _valid_ DIF currently
	 * is one where we store to a variable before loading it, so this
	 * information should already be available.
	 */
	for (i = 0; i < difo->dtdo_varlen; i++) {
		var = &difo->dtdo_vartab[i];

		if (dt_var_is_builtin(var->dtdv_id))
			continue;

		vlvar = dt_get_var_from_vec(var->dtdv_id,
		    var->dtdv_scope, var->dtdv_kind);
		assert(vlvar != nullptr);

		var->dtdv_type = vlvar->dtdv_type;
		id = var->dtdv_id;
		scope = var->dtdv_scope;

		biggest_type[scope][id] = biggest_type[scope][id].dtdt_size >=
			var->dtdv_type.dtdt_size ?
			  biggest_type[scope][id] :
			  var->dtdv_type;
	}
}

static void
finalize_vartab(dtrace_difo_t *difo, dtrace_diftype_t **biggest_type)
{
	size_t i;
	dtrace_difv_t *var;

	/*
	 * Re-patch the variable table to ensure that we have uniform types
	 * across all of the references of the variable. Without this, the
	 * kernel verifier will fail.
	 */
	for (i = 0; i < difo->dtdo_varlen; i++) {
		var = &difo->dtdo_vartab[i];

		if (dt_var_is_builtin(var->dtdv_id))
			continue;

		var->dtdv_type = biggest_type[var->dtdv_scope][var->dtdv_id];
	}

}

static int
process_difo(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_actdesc_t *ad,
    dtrace_difo_t *difo, dtrace_ecbdesc_t *ecbdesc,
    dtrace_diftype_t **biggest_vartype)
{
	int rval;
	dtrace_actkind_t actkind;
	dtrace_diftype_t saved_rtype;
	TypeInference ti(dtp, pgp);

	rval = dt_compute_dfg(dtp, pgp, ecbdesc, difo);
	if (rval != 0)
		return (rval);

	saved_rtype = difo->dtdo_rtype;
	rval = ti.inferDIFO(difo);
	if (rval != 0)
		return (rval);

	dt_prog_infer_usetxs(difo);

	actkind = ad == nullptr ? DTRACEACT_DIFEXPR : ad->dtad_kind;
	rval = dt_prog_relocate(dtp, pgp, actkind, ad, difo, &saved_rtype);
	if (rval != 0)
		return (rval);

	dt_prog_assemble(dtp, pgp, difo, biggest_vartype);
	return (0);
}

}

int
dtrace_relocate(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	using namespace dtrace;

	dt_stmt_t *stp = nullptr;
	dtrace_stmtdesc_t *sdp = nullptr;
	dtrace_actdesc_t *ad = nullptr;
	dtrace_ecbdesc_t *ecbdesc;
	dtrace_preddesc_t *pred;
	std::unordered_set<dtrace_ecbdesc_t *> processed_ecbdescs;
	int rval = 0;
	int err = 0;
	int i;
	dtrace_diftype_t *biggest_vartype[DIFV_NSCOPES];

	dt_typefile_openall(dtp);
	if (err)
		errx(EXIT_FAILURE, "failed to open CTF files: %s\n",
		    strerror(errno));

	dt_prepare_typestrings(dtp, pgp);

	dfg_nodes.clear();
	basic_blocks.clear();
	var_vector.clear();

	dfg_nodes.push_front(std::make_unique<dfg_node>(dtp, pgp, nullptr,
	    nullptr, nullptr, UINT_MAX));
	r0node = dfg_nodes.front().get();
	r0node->d_type = DIF_TYPE_BOTTOM;

	/*
	 * Regenerate the identifier, since it's no longer the same program. Set
	 * the srcident to the original identifier.
	 */
	memcpy(pgp->dp_srcident, pgp->dp_ident, DT_PROG_IDENTLEN);
	dt_prog_generate_ident(pgp);

	for (i = 0; i < DIFV_NSCOPES; i++) {
		biggest_vartype[i] = (dtrace_diftype_t *)malloc(
		    sizeof(dtrace_diftype_t) * DIF_VARIABLE_MAX);
		if (biggest_vartype[i] == nullptr)
			dt_set_progerr(dtp, pgp,
			    "could not allocate biggest_vartype\n");

		memset(biggest_vartype[i], 0,
		    sizeof(dtrace_diftype_t) * DIF_VARIABLE_MAX);
	}

	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		sdp = stp->ds_desc;

		if (sdp == nullptr) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_NOSTMT));
		}

		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == nullptr) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_DIFINVAL));
		}

		pred = &ecbdesc->dted_pred;
		assert(pred != nullptr);

		if (pred->dtpdd_difo != nullptr)
			dt_populate_varlist(dtp, pred->dtpdd_difo);

		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == nullptr)
			continue;

		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == nullptr) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_ACTLAST));
		}

		/*
		 * We populate the variable list before we actually do a pass
		 * to infer definitions or type-checking. The reason for this
		 * is to do with the semantics of probes being concurrent, in
		 * the sense that they are in fact in parallel composition with
		 * each other, rather than having some sort of ordering. Even
		 * though for now we simply adopt the D style of type checking
		 * for variables (store before a load), we would also like for
		 * this to type-check:
		 *
		 * foo { y = x; } bar { x = 1; }
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == nullptr)
				continue;

			dt_populate_varlist(dtp, ad->dtad_difo);
		}
	}
	/*
	 * Go over all the statements in a D program
	 */
	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		sdp = stp->ds_desc;
		if (sdp == nullptr) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_NOSTMT));
		}

		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == nullptr) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_DIFINVAL));
		}

		pred = &ecbdesc->dted_pred;
		assert(pred != nullptr);

		if (pred->dtpdd_difo != nullptr) {
			if (!processed_ecbdescs.contains(ecbdesc)) {
				rval = process_difo(dtp, pgp, nullptr,
				    pred->dtpdd_difo, ecbdesc, biggest_vartype);
				if (rval != 0) {
					for (i = 0; i < DIFV_NSCOPES; i++)
						free(biggest_vartype[i]);
					return (dt_set_errno(dtp, rval));
				}

				processed_ecbdescs.insert(ecbdesc);
			}
		}
		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == nullptr)
			continue;

		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == nullptr) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_ACTLAST));
		}

		/*
		 * We go over each action and apply the relocations in each
		 * DIFO (if it exists).
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == nullptr)
				continue;

			rval = process_difo(dtp, pgp, ad, ad->dtad_difo,
			    ecbdesc, biggest_vartype);
			if (rval != 0) {
				for (i = 0; i < DIFV_NSCOPES; i++)
					free(biggest_vartype[i]);
				return (dt_set_errno(dtp, rval));
			}
		}
	}

	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		/*
		 * We don't need any checks here, because we just passed them
		 * above.
		 */
		sdp = stp->ds_desc;
		ecbdesc = sdp->dtsd_ecbdesc;
		pred = &ecbdesc->dted_pred;

		if (pred->dtpdd_difo != nullptr)
			finalize_vartab(pred->dtpdd_difo, biggest_vartype);

		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == nullptr)
			continue;

		/*
		 * Finalize the variable table for each DIFO.
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == nullptr)
				continue;

			finalize_vartab(ad->dtad_difo, biggest_vartype);
		}
	}

	for (i = 0; i < DIFV_NSCOPES; i++)
		free(biggest_vartype[i]);

	return (0);
}
