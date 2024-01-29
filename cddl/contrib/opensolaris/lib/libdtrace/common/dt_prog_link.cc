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
#include <dt_hypertrace_linker.hh>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>

#ifndef illumos
#include <sys/sysctl.h>
#endif

namespace dtrace {

using std::array;
template <typename T> using vec = std::vector<T>;
template <typename T> using uptr = std::unique_ptr<T>;

HyperTraceLinker::HyperTraceLinker(dtrace_hdl_t *_dtp, dtrace_prog_t *_pgp)
    : dtp(_dtp)
    , pgp(_pgp)
{
}

void
HyperTraceLinker::patchUsetxDefs(DFGNode *n)
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

	for (auto node : n->usetxDefs) {
		if (node->isRelocated)
			continue;

		instr = node->getInstruction();
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

		node->DIFOBuf()[node->uidx] = DIF_INSTR_SETX(index, rd);
		node->isRelocated = true;
	}
}

void
HyperTraceLinker::relocateUloadOrAdd(DFGNode *node)
{
	size_t size, kind;
	ctf_id_t ctfid;
	uint8_t rd, r1;
	uint8_t opcode, new_op;
	ctf_encoding_t encoding;
	dif_instr_t instr, new_instr;

	instr = node->getInstruction();
	opcode = DIF_INSTR_OP(instr);

	if (opcode == DIF_OP_ADD) {
		goto usetx_relo;
	}

	ctfid = node->tf->resolve(node->mip->ctm_type);
	size = node->tf->getSize(ctfid);
	kind = node->tf->getKind(ctfid);


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
		if (node->tf->getEncoding(ctfid, &encoding) != 0)
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
			node->isRelocated = true;
			return;
		}

		mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
		assert(mip != nullptr);

		memset(mip, 0, sizeof(*mip));
		auto type = node->tf->getReference(node->ctfid);
		if (node->tf->getMembInfo(type, node->sym, mip) == 0) {
			dt_set_progerr(dtp, pgp,
			    "%s(%p[%zu]): failed to get mip: %s.%s: %s\n",
			    __func__, node->difo, node->uidx,
			    node->tf->getTypename(node->ctfid)
				.value_or("UNKNOWN")
				.c_str(),
			    node->sym, node->tf->getErrMsg());
		}

		node->mip = mip;
	}

	patchUsetxDefs(node);

	if (opcode != DIF_OP_ADD)
		node->DIFOBuf()[node->uidx] = new_instr;
	node->isRelocated = true;
}

void
HyperTraceLinker::relocateRetOrPush(DFGNode *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *orig_rtype)
{

	/*
	 * If this instruction does not come from a usetx,
	 * we don't really have to do anything with it.
	 */
	if (node->mip == nullptr)
		return;

	patchUsetxDefs(node);
}

void
HyperTraceLinker::relocatePush(DFGNode *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *orig_rtype)
{

	relocateRetOrPush(node, actkind, ad, orig_rtype);
}

static void
retCleanup(DFGNode *node, dtrace_diftype_t *rtype)
{
	/*
	 * We only need to clean up things if we return by reference
	 * currently.
	 */
	if ((rtype->dtdt_flags & DIF_TF_BYREF) == 0 &&
	    (rtype->dtdt_flags & DIF_TF_BYUREF) == 0)
		return;

	for (auto n : node->r1Defs) {
		dif_instr_t instr = n->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);

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
			n->DIFOBuf()[n->uidx] = DIF_INSTR_NOP;
			break;
		}
	}
}

void
HyperTraceLinker::relocateRet(DFGNode *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *orig_rtype)
{
	dtrace_diftype_t *rtype;
	dtrace_difo_t *difo;
	ctf_id_t return_ctfid;
	int ctf_kind;

	/*
	 * In case of a RET, we first patch up the DIFO with the correct return
	 * type and size.
	 */
	difo = node->difo;
	rtype = &difo->dtdo_rtype;

	rtype->dtdt_kind = node->dType;
	if (node->dType == DIF_TYPE_CTF)
		rtype->dtdt_ckind = node->ctfid;
	else if (node->dType == DIF_TYPE_STRING)
		rtype->dtdt_ckind = DT_STR_TYPE(dtp);
	else if (node->dType == DIF_TYPE_BOTTOM)
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
		    node->dType, node->uidx);

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
			ctf_kind = node->tf->getKind(node->ctfid);

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

			retCleanup(node, rtype);

			if (rtype->dtdt_flags & DIF_TF_BYREF) {
				return_ctfid = node->tf->getReference(
				    node->ctfid);
				/*
				 * FIXME:. This is very much a heuristic. This
				 * can probably be done better.
				 */
				return_ctfid = return_ctfid == CTF_ERR ?
				    node->ctfid :
				    return_ctfid;
				rtype->dtdt_size = node->tf->getSize(
				    return_ctfid);
			} else {
				rtype->dtdt_size = node->tf->getSize(
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
	if (node->dType == DIF_TYPE_STRING) {
		rtype->dtdt_flags |= DIF_TF_BYREF;
		rtype->dtdt_ckind = CTF_ERR;
	}

	relocateRetOrPush(node, actkind, ad, orig_rtype);
}

static void
patchSETXInstructions(NodeSet *setx_defs1, NodeSet *setx_defs2)
{
	NodeSet::iterator it1, it2;
	for (it1 = setx_defs1->begin(), it2 = setx_defs2->begin();
	     it1 != setx_defs1->end() && it2 != setx_defs2->end();
	     ++it1, ++it2) {
		auto sd1 = *it1;
		auto sd2 = *it2;

		sd1->DIFOBuf()[sd1->uidx] = DIF_INSTR_NOP;
		sd2->DIFOBuf()[sd2->uidx] = DIF_INSTR_NOP;
	}
}

static bool
checkSETXDefs(NodeSet *setx_defs1, NodeSet *setx_defs2)
{
	DFGNode *sd1, *sd2;
	dif_instr_t instr1, instr2;
	uint8_t op1, op2;
	NodeSet::iterator it1, it2;

	for (it1 = setx_defs1->begin(), it2 = setx_defs2->begin();
	     it1 != setx_defs1->end() && it2 != setx_defs2->end();
	     ++it1, ++it2) {
		sd1 = *it1;
		sd2 = *it2;

		instr1 = sd1->getInstruction();
		instr2 = sd2->getInstruction();

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

void
HyperTraceLinker::relocateDFGNode(DFGNode *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_difo_t *difo, dtrace_diftype_t *orig_rtype)
{
	dif_instr_t instr;
	uint8_t opcode;

	if (node->difo != difo)
		return;

	instr = node->getInstruction();
	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_RET:
		relocateRet(node, actkind, ad, orig_rtype);
		break;

	case DIF_OP_PUSHTR:
		relocatePush(node, actkind, ad, orig_rtype);
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
		    node->dType, rv, rs);
		node->DIFOBuf()[node->uidx] = newinstr;
		break;
	}

	case DIF_OP_ADD:
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
		relocateUloadOrAdd(node);
		break;

	case DIF_OP_TYPECAST: {
		dif_instr_t idef1, idef2;
		uint8_t opdef1, opdef2;
		uint8_t r11, r12, r21, r22, currd, rd;
		NodeSet *setx_defs1, *setx_defs2, *defs;
		std::string symname;
		uint16_t sym;
		size_t l;

		/*
		 * For typecast, we simply turn it into a nop. We only
		 * ever use typecast for type inference and can't
		 * actually execute it as an instruction. We will
		 * collapse the nops later.
		 */
		node->DIFOBuf()[node->uidx] = DIF_INSTR_NOP;

		if (node->uidx < 2)
			goto end;

		patchUsetxDefs(node);
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
		for (auto ndef1 : node->r1Defs) {
			idef1 = ndef1->getInstruction();
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
				defs = &ndef1->r1Defs;
				setx_defs1 = &ndef1->r2Defs;
			}

			if (r21 == currd) {
				/*
				 * Assert that we don't have a sra %r1, %r1, %r1
				 * as that would be extremely weird.
				 */
				assert(defs == nullptr);
				assert(setx_defs1 == nullptr);
				defs = &ndef1->r2Defs;
				setx_defs1 = &ndef1->r1Defs;
			}

			if (defs == nullptr)
				continue;

			for (auto ndef2 : *defs) {
				idef2 = ndef2->getInstruction();
				opdef2 = DIF_INSTR_OP(idef2);

				if (opdef2 != DIF_OP_SLL)
					continue;

				r12 = DIF_INSTR_R1(idef2);
				r22 = DIF_INSTR_R2(idef2);

				rd = DIF_INSTR_RD(idef2);

				setx_defs2 = nullptr;
				if (r12 == rd)
					setx_defs2 = &ndef2->r2Defs;

				if (r22 == rd)
					setx_defs2 = &ndef2->r1Defs;

				if (setx_defs2 == nullptr)
					continue;

				if (!checkSETXDefs(setx_defs1, setx_defs2))
					continue;

				ndef2->DIFOBuf()[ndef2->uidx] = DIF_INSTR_NOP;
				ndef1->DIFOBuf()[ndef1->uidx] = DIF_INSTR_NOP;

				patchSETXInstructions(setx_defs1, setx_defs2);
			}
		}

end:
		node->isRelocated = true;
		break;
	}

	default:
		break;
	}
}

int
HyperTraceLinker::relocateProgram(dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_difo_t *difo, dtrace_diftype_t *orig_rtype)
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

	for (auto &n : dfgNodes) {
		if (n.get() == r0node)
			continue;
		relocateDFGNode(n.get(), actkind, ad, difo,
		    orig_rtype);
	}

	return (0);
}

void
HyperTraceLinker::updateUsetxDefsInBB(dtrace_difo_t *difo, BasicBlock *bb, DFGNode *n)
{
	if (n->sym == nullptr)
		errx(EXIT_FAILURE, "usetx din_sym should not be nullptr");

	for (auto &node : dfgNodes) {
		if (node.get() == r0node)
			continue;

		dif_instr_t instr = node->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);

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
			auto usetx_node = node->findChild(n);
			if (usetx_node != n)
				continue;

			node->usetxDefs.insert(n);
		}
	}
}

void
HyperTraceLinker::updateUsetxDefs(dtrace_difo_t *difo, BasicBlock *bb, DFGNode *n)
{
	updateUsetxDefsInBB(difo, bb, n);

	for (auto child : bb->children) {
		updateUsetxDefs(difo, child.first, n);
	}
}

void
HyperTraceLinker::inferUsetxDefs(dtrace_difo_t *difo)
{
	BasicBlock *bb = static_cast<BasicBlock *>(difo->dtdo_bb);

	for (auto it = dfgNodes.rbegin(); it != dfgNodes.rend(); ++it) {
		auto n = it->get();
		assert(n != nullptr);

		if (n->sym == nullptr)
			continue;

		if (n->difo != difo)
			continue;

		dif_instr_t instr = n->getInstruction();
		uint8_t opcode = DIF_INSTR_OP(instr);

		if (opcode != DIF_OP_USETX)
			continue;

		updateUsetxDefs(difo, bb, n);
	}
}

void
HyperTraceLinker::assembleProgram(dtrace_difo_t *difo,
    array<umap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &biggest_type)
{
	if (difo->dtdo_inthash != nullptr) {
		size_t inthash_size = dt_inttab_size(difo->dtdo_inthash);
		if (inthash_size == 0) {
			fprintf(stderr, "inthash_size is 0\n");
			return;
		}

		uint64_t *otab = difo->dtdo_inttab;
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
	for (auto i = 0; i < difo->dtdo_varlen; i++) {
		dtrace_difv_t *var = &difo->dtdo_vartab[i];

		if (dt_var_is_builtin(var->dtdv_id))
			continue;

		dtrace_difv_t *vlvar = getVarFromVarVec(var->dtdv_id,
		    var->dtdv_scope, var->dtdv_kind);
		assert(vlvar != nullptr);

		var->dtdv_type = vlvar->dtdv_type;
		auto id = var->dtdv_id;
		auto scope = var->dtdv_scope;

		assert(scope < DIFV_NSCOPES);
		auto bt_size = biggest_type[scope][id].dtdt_size;
		auto vt_size = var->dtdv_type.dtdt_size;
		if (bt_size < vt_size)
			biggest_type[scope][id] = var->dtdv_type;
	}
}

static void
finalizeVartab(dtrace_difo_t *difo,
    array<umap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &biggest_type)
{
	/*
	 * Re-patch the variable table to ensure that we have uniform types
	 * across all of the references of the variable. Without this, the
	 * kernel verifier will fail.
	 */
	for (auto i = 0; i < difo->dtdo_varlen; i++) {
		dtrace_difv_t *var = &difo->dtdo_vartab[i];
		if (dt_var_is_builtin(var->dtdv_id))
			continue;

		var->dtdv_type = biggest_type[var->dtdv_scope][var->dtdv_id];
	}

}

int
HyperTraceLinker::processDIFO(dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_ecbdesc_t *ecbdesc,
    array<umap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &biggest_vartype)
{
	int rval;
	dtrace_actkind_t actkind;
	dtrace_diftype_t saved_rtype;
	TypeInference ti(*this, dtp, pgp);

	rval = computeDFG(ecbdesc, difo);
	if (rval != 0)
		return (rval);

	saved_rtype = difo->dtdo_rtype;
	rval = ti.inferDIFO(difo);
	if (rval != 0)
		return (rval);

	inferUsetxDefs(difo);

	actkind = ad == nullptr ? DTRACEACT_DIFEXPR : ad->dtad_kind;
	rval = relocateProgram(actkind, ad, difo, &saved_rtype);
	if (rval != 0)
		return (rval);

	assembleProgram(difo, biggest_vartype);
	return (0);
}

int
HyperTraceLinker::link(void)
{

	dt_stmt_t *stp;
	dtrace_stmtdesc_t *sdp;
	dtrace_actdesc_t *ad;
	dtrace_ecbdesc_t *ecbdesc;
	dtrace_preddesc_t *pred;
	std::unordered_set<dtrace_ecbdesc_t *> processed_ecbdescs;
	int rval, err, i;
	array<umap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> biggest_vartype;

	dt_typefile_openall(dtp);
	dfgNodes.push_front(std::make_unique<DFGNode>(dtp, pgp, nullptr,
	    nullptr, nullptr, UINT_MAX));
	r0node = dfgNodes.front().get();
	r0node->dType = DIF_TYPE_BOTTOM;

	/*
	 * Regenerate the identifier, since it's no longer the same program. Set
	 * the srcident to the original identifier.
	 */
	memcpy(pgp->dp_srcident, pgp->dp_ident, DT_PROG_IDENTLEN);
	dt_prog_generate_ident(pgp);

	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		sdp = stp->ds_desc;

		if (sdp == nullptr)
			return (dt_set_errno(dtp, EDT_NOSTMT));

		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == nullptr)
			return (dt_set_errno(dtp, EDT_DIFINVAL));

		pred = &ecbdesc->dted_pred;
		assert(pred != nullptr);

		if (pred->dtpdd_difo != nullptr)
			populateVariablesFromDIFO(pred->dtpdd_difo);

		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == nullptr)
			continue;

		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == nullptr)
			return (dt_set_errno(dtp, EDT_ACTLAST));

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

			populateVariablesFromDIFO(ad->dtad_difo);
		}
	}
	/*
	 * Go over all the statements in a D program
	 */
	for (stp = (dt_stmt_t *)dt_list_next(&pgp->dp_stmts); stp;
	     stp = (dt_stmt_t *)dt_list_next(stp)) {
		sdp = stp->ds_desc;
		if (sdp == nullptr)
			return (dt_set_errno(dtp, EDT_NOSTMT));

		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == nullptr)
			return (dt_set_errno(dtp, EDT_DIFINVAL));

		pred = &ecbdesc->dted_pred;
		assert(pred != nullptr);

		if (pred->dtpdd_difo != nullptr) {
			if (!processed_ecbdescs.contains(ecbdesc)) {
				rval = processDIFO(nullptr, pred->dtpdd_difo,
				    ecbdesc, biggest_vartype);
				if (rval != 0)
					return (dt_set_errno(dtp, rval));

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
		if (sdp->dtsd_action_last == nullptr)
			return (dt_set_errno(dtp, EDT_ACTLAST));

		/*
		 * We go over each action and apply the relocations in each
		 * DIFO (if it exists).
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == nullptr)
				continue;

			rval = processDIFO(ad, ad->dtad_difo, ecbdesc,
			    biggest_vartype);
			if (rval != 0)
				return (dt_set_errno(dtp, rval));
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
			finalizeVartab(pred->dtpdd_difo, biggest_vartype);

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

			finalizeVartab(ad->dtad_difo, biggest_vartype);
		}
	}

	return (0);
}

}

int
hypertrace_link(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dtrace::HyperTraceLinker l(dtp, pgp);
	return (l.link());
}
