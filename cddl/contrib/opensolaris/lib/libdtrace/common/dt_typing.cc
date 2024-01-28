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

#include <dt_typing.hh>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_linker_subr.hh>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_typefile.hh>
#include <dt_typing_helpers.hh>
#include <dt_typing_var.hh>

#include <string>
#include <unordered_map>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

namespace dtrace {

TypeInference::TypeInference(dtrace_hdl_t *_dtp, dtrace_prog_t *_pgp)
    : dtp(_dtp)
    , pgp(_pgp)
{
}

static int
dt_setx_value(dtrace_difo_t *difo, dif_instr_t instr)
{
	uint8_t opcode;
	uint16_t index;

	opcode = DIF_INSTR_OP(instr);
	assert(opcode == DIF_OP_SETX);
	assert(difo->dtdo_inttab != nullptr);

	index = DIF_INSTR_INTEGER(instr);
	assert(index < difo->dtdo_intlen);

	return (difo->dtdo_inttab[index]);
}

/*
 * This is the main part of the type inference algorithm.
 */
int
TypeInference::inferNode(dfg_node *n)
{
	dfg_node *dn1, *dn2, *dnv, *tc_n,
	    *symnode, *other, *var_stacknode, *node,
	    *data_dn1 = nullptr, *data_dn2 = nullptr;
	int type1, type2, res, i, t;
	char buf[4096] = { 0 }, symname[4096] = { 0 }, var_type[4096] = { 0 };
	ctf_membinfo_t *mip;
	size_t l;
	uint16_t var;
	dtrace_difo_t *difo;
	dif_instr_t instr, dn1_instr;
	uint8_t opcode, dn1_op, idx;
	uint16_t sym;
	ctf_id_t type = 0;
	dtrace_difv_t *dif_var;
	node_vec *stack;
	int empty;
	ctf_id_t varkind;
	size_t userland_len = strlen("userland ");
	int kind;
	int c;

	if (n == r0node)
		return (n->d_type);

	std::unordered_map<std::uint8_t, std::string> insname = {
		{DIF_OP_OR,          "or"},
		{DIF_OP_XOR,        "xor"},
		{DIF_OP_AND,        "and"},
		{DIF_OP_SLL,        "sll"},
		{DIF_OP_SRL,        "srl"},
		{DIF_OP_SUB,        "sub"},
		{DIF_OP_ADD,        "add"},
		{DIF_OP_MUL,        "mul"},
		{DIF_OP_SDIV,       "sdiv"},
		{DIF_OP_UDIV,       "udiv"},
		{DIF_OP_SREM,       "srem"},
		{DIF_OP_UREM,       "urem"},
		{DIF_OP_NOT,        "not"},
		{DIF_OP_MOV,        "mov"},
		{DIF_OP_CMP,        "cmp"},
		{DIF_OP_TST,        "tst"},
		{DIF_OP_BA,         "ba"},
		{DIF_OP_BE,         "be"},
		{DIF_OP_BNE,        "bne"},
		{DIF_OP_BG,         "bg"},
		{DIF_OP_BGU,        "bgu"},
		{DIF_OP_BGE,        "bge"},
		{DIF_OP_BGEU,       "bgeu"},
		{DIF_OP_BL,         "bl"},
		{DIF_OP_BLU,        "blu"},
		{DIF_OP_BLE,        "ble"},
		{DIF_OP_BLEU,       "bleu"},
		{DIF_OP_LDSB,       "ldsb"},
		{DIF_OP_LDSH,       "ldsh"},
		{DIF_OP_LDSW,       "ldsw"},
		{DIF_OP_LDUB,       "ldub"},
		{DIF_OP_LDUH,       "lduh"},
		{DIF_OP_LDUW,       "lduw"},
		{DIF_OP_LDX,        "ldx"},
		{DIF_OP_RET,        "ret"},
		{DIF_OP_NOP,        "nop"},
		{DIF_OP_SETX,       "setx"},
		{DIF_OP_SETS,       "sets"},
		{DIF_OP_SCMP,       "scmp"},
		{DIF_OP_LDGA,       "ldga"},
		{DIF_OP_LDGS,       "ldgs"},
		{DIF_OP_STGS,       "stgs"},
		{DIF_OP_LDTA,       "ldta"},
		{DIF_OP_LDTS,       "ldts"},
		{DIF_OP_STTS,       "stts"},
		{DIF_OP_SRA,        "sra"},
		{DIF_OP_CALL,       "call"},
		{DIF_OP_PUSHTR,     "pushtr"},
		{DIF_OP_PUSHTV,     "pushtv"},
		{DIF_OP_POPTS,      "popts"},
		{DIF_OP_FLUSHTS,    "flushts"},
		{DIF_OP_LDGAA,      "ldgaa"},
		{DIF_OP_LDTAA,      "ldtaa"},
		{DIF_OP_STGAA,      "stgaa"},
		{DIF_OP_STTAA,      "sttaa"},
		{DIF_OP_LDLS,       "ldls"},
		{DIF_OP_STLS,       "stls"},
		{DIF_OP_ALLOCS,     "allocs"},
		{DIF_OP_COPYS,      "copys"},
		{DIF_OP_STB,        "stb"},
		{DIF_OP_STH,        "sth"},
		{DIF_OP_STW,        "stw"},
		{DIF_OP_STX,        "stx"},
		{DIF_OP_ULDSB,      "uldsb"},
		{DIF_OP_ULDSH,      "uldsh"},
		{DIF_OP_ULDSW,      "uldsw"},
		{DIF_OP_ULDUB,      "uldub"},
		{DIF_OP_ULDUH,      "ulduh"},
		{DIF_OP_ULDUW,      "ulduw"},
		{DIF_OP_ULDX,       "uldx"},
		{DIF_OP_RLDSB,      "rldsb"},
		{DIF_OP_RLDSH,      "rldsh"},
		{DIF_OP_RLDSW,      "rldsw"},
		{DIF_OP_RLDUB,      "rldub"},
		{DIF_OP_RLDUH,      "rlduh"},
		{DIF_OP_RLDUW,      "rlduw"},
		{DIF_OP_RLDX,       "rldx"},
		{DIF_OP_XLATE,      "xlate"},
		{DIF_OP_XLARG,      "xlarg"},
		{DIF_OP_HYPERCALL,  "hypercall"},
		{DIF_OP_USETX,      "usetx"},
		{DIF_OP_ULOAD,      "uload"},
		{DIF_OP_UULOAD,     "uuload"},
		{DIF_OP_TYPECAST,   "typecast"},
	};

	empty = 1;
	var_stacknode = node = nullptr;
	type1 = -1;
	type2 = -1;
	mip = nullptr;
	l = 0;
	difo = n->difo;
	dn1_instr = 0;
	dn1_op = 0;
	sym = 0;
	res = 0;
	tc_n = nullptr;
	symnode = nullptr;
	other = nullptr;
	var = 0;
	i = 0;
	t = 0;
	dif_var = nullptr;

	/*
	 * If we already have the type, we just return it.
	 */
	if (n->d_type != -1)
		return (n->d_type);

	/*
	 * We do not tolerate nullptr ECBs.
	 */
	assert(n->edp != nullptr);
	instr = n->get_instruction();
	opcode = DIF_INSTR_OP(instr);

	dn1 = checkRegDefs(n, n->r1_defs, &empty);
	if (dn1 == nullptr && empty == 0) {
		fprintf(stderr,
		    "inferNode(%s, %zu@%p): inferring types "
		    "for r1defs failed\n",
		    insname[opcode].c_str(), n->uidx, n->difo);
		return (-1);
	}

	dn2 = checkRegDefs(n, n->r2_defs, &empty);
	if (dn2 == nullptr && empty == 0) {
		fprintf(stderr,
		    "inferNode(%s, %zu@%p): inferring types "
		    "for r2defs failed\n",
		    insname[opcode].c_str(), n->uidx, n->difo);
		return (-1);
	}

	dnv = dt_typecheck_vardefs(n, difo, n->var_defs, &empty);
	if (dnv == nullptr && empty == 0) {
		fprintf(stderr,
		    "inferNode(%s, %zu@%p): inferring types "
		    "for vardefs failed\n",
		    insname[opcode].c_str(), n->uidx, n->difo);
		return (-1);
	}

	stack = checkStack(n, n->stacks, &empty);
	if (stack == nullptr && empty == 0) {
		fprintf(stderr,
		    "inferNode(%s, %zu@%p): inferring types "
		    "for stack failed\n",
		    insname[opcode].c_str(), n->uidx, n->difo);
		return (-1);
	}

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
		/*
		 *  %r1 : t1 | sym    sym in range(symtab)
		 *        symtab(sym) = symname
		 *       t2 = type_at(t1, symname)
		 * ----------------------------------------
		 *      opcode [%r1], %r2 => %r2 : t2
		 */

		/*
		 * We only need one type here (the first one).
		 */
		if (dn1 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn1 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		/*
		 * If there is no symbol here, we can't do anything.
		 */
		if (dn1->sym == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn1 symbol is empty\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		mip = dt_mip_from_sym(dn1);
		if (mip == nullptr) {
			dt_set_progerr(dtp, pgp,
			    "%s(%s, %zu@%p): failed to get mip: %s.%s: %s\n",
			    __func__, insname[opcode].c_str(), n->uidx, n->difo,
			    dn1->tf->get_typename(dn1->ctfid)
				.value_or("UNDEFINED")
				.c_str(),
			    dn1->sym, dn1->tf->get_errmsg());
			return (-1);
		}

		n->mip = mip;
		n->ctfid = mip->ctm_type;
		n->d_type = DIF_TYPE_CTF;
		n->tf = dn1->tf;
		return (n->d_type);


	case DIF_OP_USETX:
		/*
		 *  symtab(idx) = sym    idx in range(symtab)
		 * ------------------------------------------
		 *   usetx idx, %r1 => %r1 : uint64_t | sym
		 */

		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): "
			    "sym (%u) >= symlen (%" PRIu64 ")\n",
			    insname[opcode].c_str(), n->uidx, n->difo, sym,
			    difo->dtdo_symlen);
			return (-1);
		}

		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("uint64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get "
			    "type uint64_t: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->sym = difo->dtdo_symtab + sym;
		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);

	case DIF_OP_TYPECAST:
		/*  symtab(idx) = t   idx in range(symtab)    t in ctf_file
		 * ---------------------------------------------------------
		 *                typecast idx, %r1 => %r1 : t
		 */

		if (dn1 == nullptr)
			return (-1);

		mip = dt_mip_from_sym(dn1);
		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): "
			    "sym (%u) >= symlen (%" PRIu64 ")\n",
			    insname[opcode].c_str(), n->uidx, n->difo, sym,
			    difo->dtdo_symlen);
			return (-1);
		}

		l = strlcpy(symname, difo->dtdo_symtab + sym, sizeof(symname));
		if (l >= sizeof(symname))
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): "
			    "length (%zu) >= %zu when copying type name",
			    insname[opcode].c_str(), n->uidx, n->difo, l,
			    sizeof(symname));

		if (strncmp(symname, "userland ", userland_len) == 0) {
			char *tmpbuf;

			tmpbuf = (char *)malloc(sizeof(symname));
			if (tmpbuf == nullptr)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): "
				    "malloc() failed: %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    strerror(errno));

			memcpy(tmpbuf, symname + userland_len,
			    sizeof(symname) - userland_len);
			memcpy(symname, tmpbuf, sizeof(symname));
		}

		/*
		 * We kind of have to guess here. We start by getting the
		 * 'module' field of the probe description and try to find that
		 * module. If we can't, this might be a SDT probe that is
		 * "poorly" defined. We then look for the type in the kernel
		 * itself. If we can't find it there, we just bail out for now
		 * rather than causing runtime failures.
		 *
		 * TODO: Maybe we can tolerate some failures by looking at
		 * symbols too?
		 */
		if (strcmp(symname, "D string") == 0) {
			n->d_type = DIF_TYPE_STRING;
			n->mip = mip;
			return (n->d_type);
		}

		if (strcmp(symname, "bottom") == 0) {
			n->d_type = DIF_TYPE_BOTTOM;
			n->mip = mip;
			return (n->d_type);
		}

		n->ctfid = dt_autoresolve_ctfid(n->edp->dted_probe.dtpd_mod,
		    symname, &n->tf);
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get "
			    "type %s: %s",
			    insname[opcode].c_str(), n->uidx, n->difo, symname,
			    n->tf->get_errmsg());

		n->mip = mip;
		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);
	/*
	 * Potential information necessary to apply relocations
	 */
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_SRA:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
		/*
		 * In this rule, we allow %r1 and %r2 to be swapped.
		 * For the sake of conciseness, we just write out 1 rule.
		 *
		 *  %r1 : t1    %r2 : t2    t2 <: t1
		 * ----------------------------------
		 *  opcode %r1, %r2, %r3 => %r3 : t1
		 *
		 * The second rule has to do with symbol resolution and should
		 * only get applied when one of the two registers contains a
		 * type annotated with a symbol (indicating that the type)
		 * originates from symbol resolution, rather than a poset
		 * relation.
		 *
		 *  %r1 : t1    %r2 : uint64_t | sym    uint64_t <: t1
		 * ----------------------------------------------------
		 *        opcode %r1, %r2, %r3 => %r3 : t1 | sym
		 *
		 * N.B.: We allow this rule to work with a whole bunch of
		 *       arithmetic operations, not only add. This is simply
		 *       because we can't possibly infer all ways that one could
		 *       arrive at a given struct member, so we simply assume
		 *       that the calculation is correct. For example, we could
		 *       have something that looks like:
		 *
		 *  usetx %r1, sym
		 *  sll %r1, %r2, %r1
		 *  srl %r1, %r2, %r1
		 *
		 * where the first %r1 would be of type uint64_t | sym.
		 * Following that, sll %r1, %r2, %r1 => %r1 : uint64_t | sym
		 * and srl %r1, %r2, %r1 => %r1 : uint64_t | sym, still knowing
		 * that this type originates from a symbol.
		 */

		/*
		 * Nonsense. We need both types.
		 */
		if (dn1 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn1 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		/*
		 * If we have no type with a symbol associated with it,
		 * we apply the first typing rule.
		 */
		if (dn1->sym == nullptr && dn2->sym == nullptr) {
			ctf_id_t k;

			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(dn1, dn2);
			assert(res == 1 || res == 2 || res == -1);

			if (res == 1) {
				tc_n = dn1;
				other = dn2;
			} else if (res == 2) {
				tc_n = dn2;
				other = dn1;
			} else {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p) nosym: types can "
				    "not be compared\n",
				    insname[opcode].c_str(), n->uidx, n->difo);
				return (-1);
			}

			k = tc_n->tf->get_kind(tc_n->ctfid);
			if (opcode == DIF_OP_ADD &&
			    (k == CTF_K_STRUCT || k == CTF_K_UNION) &&
			    other->integer.has_value()) {
				mip = dt_mip_by_offset(dtp, tc_n->tf,
				    tc_n->ctfid, other->integer.value());
				if (mip == nullptr) {
					n->d_type = tc_n->d_type;
					n->ctfid = tc_n->ctfid;
					n->tf = tc_n->tf;
					n->integer = other->integer;
					return (n->d_type);
				}

				n->d_type = DIF_TYPE_CTF;
				n->ctfid = mip->ctm_type;
				n->tf = tc_n->tf;
				n->mip = nullptr;
				n->sym = nullptr;
			} else {
				/*
				 * We don't have to sanity check these because
				 * we do it in every base case of the recursive
				 * call.
				 */
				n->d_type = tc_n->d_type;
				n->ctfid = tc_n->ctfid;
				n->tf = tc_n->tf;
				n->integer = other->integer;
			}
		} else {
			if (dn1->sym == nullptr) {
				assert(dn2->sym != nullptr);
				symnode = dn2;
				other = dn1;
			} else if (dn2->sym == nullptr) {
				assert(dn1->sym != nullptr);
				symnode = dn1;
				other = dn2;
			} else {
				uint8_t op1, op2;
				assert(dn1->sym != nullptr && dn2->sym != nullptr);

				op1 = DIF_INSTR_OP(dn1->get_instruction());
				op2 = DIF_INSTR_OP(dn2->get_instruction());
				if (op1 == DIF_OP_USETX) {
					symnode = dn1;
					other = dn2;
				} else {
					assert(op2 == DIF_OP_USETX);
					symnode = dn2;
					other = dn1;
				}
			}

			if (other->d_type == DIF_TYPE_BOTTOM ||
			    symnode->d_type == DIF_TYPE_BOTTOM)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): unexpected bottom "
				    "type (binary arithmetic operation)",
				    insname[opcode].c_str(), n->uidx, n->difo);

			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(symnode, other);
			assert(res == 1 || res == 2 || res == -1);

			if (res == -1) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): types can not be "
				    "compared\n",
				    insname[opcode].c_str(), n->uidx, n->difo);
				return (-1);
			}

			/*
			 * Get the type name of the other node
			 */
			if (other->tf->get_typename(other->ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed at getting "
				    "type name %ld for other: %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    other->ctfid, other->tf->get_errmsg());

			if (res == 1) {
				if (strcmp(buf, "uint64_t") != 0)
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): the type "
					    "of the other node must be uint64_t"
					    " if symnode->ctfid (%zu@%p) <:"
					    " other->ctfid (%zu@%p), but it "
					    "is: %s",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, symnode->uidx,
					    symnode->difo, other->uidx,
					    other->difo, buf);
			}

			/*
			 * At this point, we have ensured that the types are:
			 *  (1) Related (<: exists between t1 and t2)
			 *  (2) Well-ordered: if
			 *
			 *            symnode->ctfid <: other->ctfid,
			 *
			 *      then other->ctfid is also
			 *      uint64_t (reflexivity).
			 *  (3) One of the uint64_ts originates from a symbol.
			 */
			if (other->sym == nullptr) { // FIXME: suspect
				n->sym = symnode->sym;
				n->ctfid = other->ctfid;
				n->tf = other->tf;
				n->d_type = DIF_TYPE_CTF;
				return (n->d_type);
			}

			c = dt_get_class(other->tf, other->ctfid, 1);
			if (c != DTC_STRUCT && c != DTC_UNION)
				return (-1);

			/*
			 * Figure out t2 = type_at(t1, symname)
			 */
			mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
			if (mip == nullptr)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed to "
				    "malloc mip",
				    insname[opcode].c_str(), n->uidx, n->difo);

			memset(mip, 0, sizeof(ctf_membinfo_t));

			/*
			 * Get the non-pointer type. This should NEVER fail.
			 */
			type = other->tf->get_reference(other->ctfid);
			if (other->tf->get_membinfo(type, other->sym,
			    mip) == 0)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed to get "
				    "member info for %s(%s): %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    buf, other->sym, other->tf->get_errmsg());

			n->mip = mip;
			n->sym = symnode->sym;
			n->ctfid = mip->ctm_type;
			n->tf = other->tf;
			n->d_type = DIF_TYPE_CTF;
		}

		return (n->d_type);

	case DIF_OP_MOV:
	case DIF_OP_NOT:
		/*
		 *           %r1 : t
		 * ---------------------------
		 * opcode %r1, %r2 => %r2 : t
		 */

		/*
		 * Nonsense.
		 *
		 * N.B.: We don't need to check that type1 is sane, because
		 *       if dn1 is not nullptr, then we'll have checked it already.
		 */
		if (dn1 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn1 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		/*
		 * We don't have to sanity check here because we do it in every
		 * base case of the recursive call.
		 */
		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->d_type = dn1->d_type;
		n->mip = dn1->mip;
		n->sym = dn1->sym;

		if (opcode == DIF_OP_MOV)
			n->isnull = dn1->isnull;

		return (n->d_type);

	case DIF_OP_LDSB:
	case DIF_OP_RLDSB:
	case DIF_OP_ULDSB:
		/*
		 *          %r1 :: Pointer
		 * -----------------------------------
		 *  opcode [%r1], %r2 => %r2 : int8_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("int8_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "int8_t: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);

	case DIF_OP_LDSH:
	case DIF_OP_RLDSH:
	case DIF_OP_ULDSH:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int16_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("int16_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "int16_t: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);

	case DIF_OP_LDSW:
	case DIF_OP_RLDSW:
	case DIF_OP_ULDSW:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int32_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("int32_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get "
			    "type unsigned char: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);

	case DIF_OP_LDUB:
	case DIF_OP_RLDUB:
	case DIF_OP_ULDUB:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint8_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("uint8_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint8_t: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);

	case DIF_OP_LDUH:
	case DIF_OP_RLDUH:
	case DIF_OP_ULDUH:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint16_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("uint16_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint16_t: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);

	case DIF_OP_LDUW:
	case DIF_OP_RLDUW:
	case DIF_OP_ULDUW:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint32_t
		 */
		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("uint32_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint32_t: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->d_type = DIF_TYPE_CTF;
		return (n->d_type);

	case DIF_OP_ULDX:
	case DIF_OP_RLDX:
	case DIF_OP_LDX:
	case DIF_OP_SETX:
		/*
		 * ---------------------------------
		 *  setx idx, %r1 => %r1 : uint64_t
		 */

		n->tf = dt_typefile_D();
		n->ctfid = n->tf->get_ctfid("uint64_t");
		if (n->ctfid == CTF_ERR)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get type "
			    "uint64_t: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->tf->get_errmsg());

		n->d_type = DIF_TYPE_CTF;
		if (opcode == DIF_OP_SETX) {
			n->integer = std::make_optional<uint64_t>(
			    dt_setx_value(difo, instr));
			n->isnull = n->integer.value() == 0;
		}

		return (n->d_type);

	case DIF_OP_SETS:
		/*
		 * --------------------------------
		 *  sets idx, %r1 => %r1: D string
		 */

		n->d_type = DIF_TYPE_STRING;
		return (n->d_type);

	case DIF_OP_LDGA:
		/*
		 *   var : t[]          %r2 : int
		 * --------------------------------
		 *  ldga var, %r2,  %r1 => %r1 : t
		 */

		var = DIF_INSTR_R1(instr);
		assert(dn2 != nullptr);

		if (!dt_var_is_builtin(var)) {
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): %u "
			    "is not a built-in variable",
			    insname[opcode].c_str(), n->uidx, n->difo, var);
		}

		if (DIF_INSTR_OP(dn2->get_instruction()) != DIF_OP_SETX) {
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): %%r%u "
			    "is not assigned by a SETX instruction @ %zu",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    DIF_INSTR_R2(instr), dn2->uidx);
		}

		idx = dn2->integer.value();
		dt_builtin_type(n, var, idx);
		return (n->d_type);

	case DIF_OP_LDLS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldls var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find variable "
			    "(%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (dnv == nullptr) {
			if (dif_var == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable and dnv "
				    "don't exist\n",
				    insname[opcode].c_str(), n->uidx, n->difo);
				return (-1);
			} else {
				n->ctfid = dif_var->dtdv_ctfid;
				n->tf = v2tf(dif_var->dtdv_tf);
				n->d_type = dif_var->dtdv_type.dtdt_kind;
				n->sym = dif_var->dtdv_sym;

				return (n->d_type);
			}
		}

		if (dif_var != nullptr) {
			if (dif_var->dtdv_type.dtdt_kind != dnv->d_type) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_type.dtdt_kind, dn1->d_type);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dnv->ctfid) {
				if (dnv->tf->get_typename(dnv->ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld for dnv: %s",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dnv->ctfid,
					    dnv->tf->get_errmsg());

				if (v2tf(dif_var->dtdv_tf)->get_typename(
				    dif_var->dtdv_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld for dif_var: %s",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dif_var->dtdv_ctfid,
					    v2tf(dif_var->dtdv_tf)->get_errmsg());

				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    buf, var_type);
				return (-1);
			}

			if (dnv->sym && dif_var->dtdv_sym == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != nullptr\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dnv->sym);
				return (-1);
			}

			if (dnv->sym == nullptr && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch nullptr != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dnv->sym) != 0) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dnv->sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->ctfid = dnv->ctfid;
		n->tf = dnv->tf;
		n->d_type = dnv->d_type;
		n->mip = dnv->mip;
		n->sym = dnv->sym;

		return (n->d_type);

	case DIF_OP_LDGS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldgs var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dn1 == nullptr) {
			if (dt_var_is_builtin(var)) {
				dt_builtin_type(n, var, 0);
				return (n->d_type);
			} else if (dif_var == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable %d and "
				    "dn1 don't exist\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    var);
				return (-1);
			} else {
				n->ctfid = dif_var->dtdv_ctfid;
				n->tf = v2tf(dif_var->dtdv_tf);
				n->d_type = dif_var->dtdv_type.dtdt_kind;
				n->sym = dif_var->dtdv_sym;
				return (n->d_type);
			}
		}

		if (dif_var != nullptr) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->d_type) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_type.dtdt_kind, dn1->d_type);
				return (-1);
			}

			if (v2tf(dif_var->dtdv_tf) != dn1->tf) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable typefile "
				    "is %s, but dn1 typefile is %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    v2tf(dif_var->dtdv_tf)->name().c_str(),
				    dn1->tf->name().c_str());
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->ctfid) {
				if (dn1->tf->get_typename(dn1->ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    dn1->tf->get_errmsg());

				if (v2tf(dif_var->dtdv_tf)->get_typename(
				    dif_var->dtdv_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    v2tf(dif_var->dtdv_tf)->get_errmsg());

				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    buf, var_type);
				return (-1);
			}

			if (dn1->sym && dif_var->dtdv_sym == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != nullptr\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dn1->sym);
				return (-1);
			}

			if (dn1->sym == nullptr && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch nullptr != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->sym) != 0) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dn1->sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->d_type = dn1->d_type;
		n->mip = dn1->mip;
		n->sym = dn1->sym;

		return (n->d_type);

	case DIF_OP_LDTS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldts var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find variable "
			    "(%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (dn1 == nullptr) {
			if (dif_var == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable "
				    "and dn1 don't exist\n",
				    insname[opcode].c_str(), n->uidx, n->difo);
				return (-1);
			} else {
				n->ctfid = dif_var->dtdv_ctfid;
				n->tf = v2tf(dif_var->dtdv_tf);
				n->d_type = dif_var->dtdv_type.dtdt_kind;
				n->sym = dif_var->dtdv_sym;

				return (n->d_type);
			}
		}

		if (dif_var != nullptr) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->d_type) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_type.dtdt_kind, dn1->d_type);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->ctfid) {
				if (dn1->tf->get_typename(dn1->ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    dn1->tf->get_errmsg());

				if (v2tf(dif_var->dtdv_tf)->get_typename(
				    dif_var->dtdv_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(dtp, pgp,
					    "inferNode(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode].c_str(), n->uidx,
					    n->difo, dn1->ctfid,
					    v2tf(dif_var->dtdv_tf)->get_errmsg());

				fprintf(stderr,
				    "inferNode(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    buf, var_type);
				return (-1);
			}

			if (dn1->sym && dif_var->dtdv_sym == nullptr) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != nullptr\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dn1->sym);
				return (-1);
			}

			if (dn1->sym == nullptr && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch nullptr != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->sym) != 0) {
				fprintf(stderr,
				    "inferNode(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dn1->sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->d_type = dn1->d_type;
		n->mip = dn1->mip;
		n->sym = dn1->sym;

		return (n->d_type);

	case DIF_OP_STGS:
		/*
		 *  %r1 : t       var notin builtins
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stgs %r1, var => var : t
		 *
		 *  %r1 : t       var notin builtins
		 *         var notin var_list
		 * ----------------------------------
		 *     stgs %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		/*
		 * If we are doing a STGS, and the variable is a builtin
		 * variable, we fail to type-check the instruction.
		 */
		if (dt_var_is_builtin(var)) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): trying to store to a "
			    "builtin variable\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in stgs.\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (inferVar(n->difo, dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dif_var->dtdv_ctfid;
		n->tf = v2tf(dif_var->dtdv_tf);
		n->d_type = dif_var->dtdv_type.dtdt_kind;
		n->mip = dn2->mip;
		n->sym = dn2->sym;

		return (n->d_type);

	case DIF_OP_STTS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stts %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stts %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in stts.\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (inferVar(n->difo, dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dif_var->dtdv_ctfid;
		n->tf = v2tf(dif_var->dtdv_tf);
		n->d_type = dif_var->dtdv_type.dtdt_kind;
		n->mip = dn2->mip;
		n->sym = dn2->sym;

		return (n->d_type);

	case DIF_OP_STLS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stls %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stls %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in stls.\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (inferVar(n->difo, dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dn2->ctfid;
		n->tf = dn2->tf;
		n->d_type = dn2->d_type;
		n->mip = dn2->mip;
		n->sym = dn2->sym;

		return (n->d_type);

	case DIF_OP_LDTA:
		break;
	case DIF_OP_CALL:
		/*
		 *     subr : t1 -> t2 ... -> tn -> t
		 *  stack[0] : t1    stack[1] : t2     ...
		 *  stack[n] : tm        m = stacklen - 1
		 *                m >= n
		 * ----------------------------------------
		 *       call subr, %r1 => %r1 : t
		 */
		return (inferSubr(n, stack));

	case DIF_OP_LDGAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (n->stacks.empty()) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): stack list is "
			    "empty in ldgaa\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (checkVarStack(n, dnv, dif_var) == -1)
			return (-1);

		if (inferVar(n->difo, dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->ctfid = dnv->ctfid;
			n->tf = dnv->tf;
			n->d_type = dnv->d_type;
			n->mip = dnv->mip;
			n->sym = dnv->sym;
		} else {
			n->ctfid = dif_var->dtdv_ctfid;
			n->tf = v2tf(dif_var->dtdv_tf);
			n->d_type = dif_var->dtdv_type.dtdt_kind;
			n->sym = dif_var->dtdv_sym;
		}

		return (n->d_type);

	case DIF_OP_LDTAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): "
			    "failed to find variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (n->stacks.empty()) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): stack list is "
			    "empty in ldgaa\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (checkVarStack(n, dnv, dif_var) == -1)
			return (-1);

		if (inferVar(n->difo, dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->ctfid = dnv->ctfid;
			n->tf = dnv->tf;
			n->d_type = dnv->d_type;
			n->mip = dnv->mip;
			n->sym = dnv->sym;
		} else {
			n->ctfid = dif_var->dtdv_ctfid;
			n->tf = v2tf(dif_var->dtdv_tf);
			n->d_type = dif_var->dtdv_type.dtdt_kind;
			n->sym = dif_var->dtdv_sym;
		}

		return (n->d_type);

	/*
	 * FIXME(dstolfa): Handle STGAAs to struct types.
	 */
	case DIF_OP_STGAA:
		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in "
			    "stgaa.\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): "
			    "failed to find variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  x[curthread] = 1;
		 *  x[tid] = 2;
		 */

		if (checkVarStack(n, dn2, dif_var) == -1)
			return (-1);

		if (inferVar(n->difo, dn2, dif_var) == -1)
			return (-1);

		if (dn2->d_type != DIF_TYPE_BOTTOM) {
			n->ctfid = dn2->ctfid;
			n->tf = dn2->tf;
			n->d_type = dn2->d_type;
			n->mip = dn2->mip;
			n->sym = dn2->sym;
		} else {
			n->ctfid = dif_var->dtdv_ctfid;
			n->tf = v2tf(dif_var->dtdv_tf);
			n->d_type = dif_var->dtdv_type.dtdt_kind;
			n->mip = dn2->mip;
			n->sym = dn2->sym;
		}

		return (n->d_type);

	case DIF_OP_STTAA:
		if (dn2 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): dn2 is nullptr in sttaa.\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_vec(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode].c_str(), n->uidx, n->difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  self->x[curthread] = 1;
		 *  self->x[tid] = 2;
		 */
		if (checkVarStack(n, dn2, dif_var) == -1)
			return (-1);

		if (inferVar(n->difo, dn2, dif_var) == -1)
			return (-1);

		n->ctfid = dn2->ctfid;
		n->tf = dn2->tf;
		n->d_type = dn2->d_type;
		n->mip = dn2->mip;
		n->sym = dn2->sym;

		return (n->d_type);

	case DIF_OP_ALLOCS:
		n->ctfid = CTF_ERR;
		n->tf = nullptr;
		n->d_type = DIF_TYPE_BOTTOM;
		n->mip = nullptr;
		n->sym = nullptr;

		return (n->d_type);

	case DIF_OP_COPYS:
		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->d_type = dn1->d_type;
		n->mip = dn1->mip;
		n->sym = dn1->sym;

		return (n->d_type);

	case DIF_OP_RET:
		/*
		 * Only do this if it's a CTF type. We might be coming from a
		 * typecast.
		 */
		if (dn1->sym != nullptr) {
			typefile *tf;
			ctf_id_t ctfid;
			int type;

			tf = dn1->tf;
			type = dn1->d_type;
			ctfid = dn1->ctfid;

			/*
			 * We only need one type here (the first one).
			 */
			mip = dt_mip_from_sym(dn1);
			if (mip == nullptr) {
				dt_set_progerr(dtp, pgp,
				    "%s(%s, %zu@%p): failed to get mip from symbol (%s)",
				    __func__, insname[opcode].c_str(), n->uidx,
				    n->difo, dn1->sym);
				return (-1);
			}

			n->mip = mip;
			n->tf = dn1->tf;
#if 0
			n->ctfid =
			    dn1 == dn1 ? mip->ctm_type : dn1->ctfid;
			n->d_type =
			    dn1 == dn1 ? DIF_TYPE_CTF : dn1->d_type;
#endif
			/*
			 * FIXME(dstolfa): Is this correct??
			 * The above's idea is actually to compare data_dn1 ==
			 * dn1 rather than dn1 == dn1 (bug). However, I'm not
			 * entirely sure that we need to, because a pattern such
			 * as:
			 *
			 * usetx ..., %r1
			 * typecast ..., %r1
			 * ...
			 * ret %r1
			 *
			 * will never actually carry around a symbol in the
			 * node, so if we have the symbol, that means that the
			 * typecast instruction wasn't the one that actually
			 * defined the node, so we can't end up with data_dn1 !=
			 * dn1, and therefore this should just work.
			 */
			n->ctfid = mip->ctm_type;
			n->d_type =DIF_TYPE_CTF;
		} else {
			n->ctfid = dn1->ctfid;
			n->tf = dn1->tf;
			n->d_type = dn1->d_type;
		}

		return (n->d_type);

	case DIF_OP_PUSHTR:
		if (dn1 == nullptr) {
			fprintf(stderr,
			    "inferNode(%s, %zu@%p): pushtr dn1 is nullptr\n",
			    insname[opcode].c_str(), n->uidx, n->difo);
			return (-1);
		}

		if (dn1->sym != nullptr) {
			/*
			 * We only need one type here (the first one).
			 */

			mip = dt_mip_from_sym(dn1);
			if (mip == nullptr) {
				dt_set_progerr(dtp, pgp,
				    "%s(%s, %zu@%p): failed to get mip from symbol (%s)",
				    __func__, insname[opcode].c_str(), n->uidx,
				    n->difo, dn1->sym);
				return (-1);
			}

			n->mip = mip;
			n->ctfid = mip->ctm_type;
			n->tf = dn1->tf;
			n->d_type = DIF_TYPE_CTF;
		} else if (dn1->d_type == DIF_TYPE_CTF) {
			n->ctfid = dn1->ctfid;
			n->tf = dn1->tf;
			n->d_type = dn1->d_type;
		} else
			/*
			 * XXX: Do we need to store the typefile here?
			 */
			n->d_type = dn1->d_type;

		return (DIF_TYPE_NONE);

	case DIF_OP_PUSHTV:
		n->ctfid = dn1->ctfid;
		n->tf = dn1->tf;
		n->d_type = dn1->d_type;
		return (DIF_TYPE_NONE);

	case DIF_OP_FLUSHTS:
	case DIF_OP_POPTS:
	case DIF_OP_CMP:
	case DIF_OP_SCMP:
	case DIF_OP_HYPERCALL:
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
		return (DIF_TYPE_NONE);

	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX: {
		int insid;

		insid = opcode - DIF_OP_STB;
		assert(insid >= 0 && insid <= 3);

		assert(dn1 != nullptr);
		assert(dn2 != nullptr); /* the destination register source */

		/*
		 * If we reach a ST instruction, we need to make sure that we
		 * didn't do so by having a string or an uninitialized node.
		 */
		if (dn1->d_type == DIF_TYPE_STRING)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): can't store from a "
			    "string type (loc %zu)",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    dn1->uidx);

		if (dn1->d_type == DIF_TYPE_NONE)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): can't store "
			    "from type none (loc %zu)",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    dn1->uidx);

		/*
		 * If there is no symbol associated with our stx, this might
		 * have come from a translator which was resolved before this
		 * step. We just skip this instruction, as nothing will actually
		 * have this as a source.
		 */
		if (dn1->sym == nullptr) {
			n->d_type = dn2->d_type;
			n->ctfid = dn2->ctfid;
			n->tf = dn2->tf;
			return (n->d_type);
		}

		/*
		 * Make sure all of the variable definitions match up, pick one
		 * and check that it's a CTF type.
		 *
		 * FIXME(dstolfa): Doing something like foo[0].snd = foo->bar;
		 * can cause the "not within a variable" if a stx happens on
		 * something that had an `add` instruction later on, e.g. giving
		 * an offset into the variable. This needs to be fixed.
		 */
		dif_var = nullptr;
		for (auto dif_var : n->var_sources) {
			dtrace_difv_t *ovar = dif_var;

			if (ovar == nullptr)
				continue;

			if (dif_var->dtdv_id != ovar->dtdv_id ||
			    dif_var->dtdv_scope != ovar->dtdv_scope ||
			    dif_var->dtdv_kind != ovar->dtdv_kind) {
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): node has a "
				    "mismatch in varsources: "
				    "(%u, %u, %u) != (%u, %u, %u)",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_id, dif_var->dtdv_scope,
				    dif_var->dtdv_kind, ovar->dtdv_id,
				    ovar->dtdv_scope, ovar->dtdv_kind);
			}

			if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_CTF)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): instruction only "
				    "makes sense on CTF variable types, got %d",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_type.dtdt_kind);

			if (dif_var->dtdv_type.dtdt_kind !=
			    ovar->dtdv_type.dtdt_kind)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): node has a "
				    "mismatch in variable types: %d != %d",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_type.dtdt_kind,
				    ovar->dtdv_type.dtdt_kind);

			if (dif_var->dtdv_tf != ovar->dtdv_tf)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): node has a "
				    "mismatch in variable typefiles: %s != %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    v2tf(dif_var->dtdv_tf)->name().c_str(),
				    v2tf(ovar->dtdv_tf)->name().c_str());

			if (v2tf(dif_var->dtdv_tf)->get_typename(dif_var->dtdv_ctfid,
			    buf, sizeof(buf)) != ((char *)buf))
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "type name %ld: %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_ctfid,
				    v2tf(dif_var->dtdv_tf)->get_errmsg());

			if (v2tf(ovar->dtdv_tf)->get_typename(ovar->dtdv_ctfid,
			    buf, sizeof(var_type)) != ((char *)var_type))
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "type name %ld: %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    ovar->dtdv_ctfid,
				    v2tf(ovar->dtdv_tf)->get_errmsg());

			if (dif_var->dtdv_ctfid != ovar->dtdv_ctfid) {
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): node has a "
				    "mismatch in varsource types: %s != %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    buf, var_type);
			}
		}

		if (dif_var == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): register [%%r%d] "
			    "is not within a variable",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    n->get_rd());

		if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_CTF)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): variable %zu is not of "
			    "a CTF type",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    dif_var->dtdv_id);

		varkind = v2tf(dif_var->dtdv_tf)->get_kind(dif_var->dtdv_ctfid);

		/*
		 * Only accept structs for now -- but we might need to handle
		 * unions and arrays at some point too.
		 */
		if (varkind != CTF_K_STRUCT)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): expected a struct CTF "
			    "kind, got %d",
			    insname[opcode].c_str(), n->uidx, n->difo, varkind);

		/*
		 * At this point, we should have a membinfo pointer to the field
		 * that we will be accessing.
		 */
		mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
		if (mip == nullptr)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): malloc failed on "
			    "mip: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    strerror(errno));

		memset(mip, 0, sizeof(ctf_membinfo_t));

		if (v2tf(dif_var->dtdv_tf)->get_membinfo(dif_var->dtdv_ctfid,
		    dn1->sym, mip) == 0)
			dt_set_progerr(dtp, pgp,
			    "inferNode(%s, %zu@%p): failed to get "
			    "member info: %s",
			    insname[opcode].c_str(), n->uidx, n->difo,
			    v2tf(dif_var->dtdv_tf)->get_errmsg());

		/*
		 * If dn1 is a CTF type, we will actually type-check that
		 * we are storing a meaningful type to the destination. If
		 * instead it is a bottom type, we will simply accept whatever
		 * the type is and store it anyway.
		 */
		if (dn1->d_type == DIF_TYPE_CTF) {
			/*
			 * We will be checking all of the compatible types too,
			 * but we start with these.
			 */
			std::array<std::string, 4> dst_type = { "uint8_t",
				"uint16_t", "uint32_t", "uint64_t" };
			ctf_id_t dst_ctfid;

			if (dn1->tf->get_typename(dn1->ctfid, buf,
			    sizeof(buf)) != (char *)buf)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "type_name of %d: %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dn1->ctfid, dn1->tf->get_errmsg());

			if (v2tf(dif_var->dtdv_tf)->get_typename(dif_var->dtdv_ctfid,
			    var_type, sizeof(var_type)) != (char *)var_type)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "type_name of %d: %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    dif_var->dtdv_ctfid,
				    v2tf(dif_var->dtdv_tf)->get_errmsg());

			auto ktf = dt_typefile_kernel();
			dst_ctfid = ktf->get_ctfid(dst_type[insid].c_str());
			if (dst_ctfid == CTF_ERR)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): failed getting "
				    "ctfid from %s for %s: %s",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    ktf->name().c_str(),
				    dst_type[insid].c_str(), ktf->get_errmsg());

			if (v2tf(dif_var->dtdv_tf)->type_compat_with(dst_ctfid,
			    dn1->tf, dn1->ctfid) == 0)
				dt_set_progerr(dtp, pgp,
				    "inferNode(%s, %zu@%p): types %s "
				    "(variable field) and %s "
				    "(instruction %zu) are not compatible",
				    insname[opcode].c_str(), n->uidx, n->difo,
				    var_type, buf, dn1->uidx);
		}

		n->d_type = dn2->d_type;
		n->ctfid = dn2->ctfid;
		n->tf = dn2->tf;
		return (n->d_type);
	} /* case DIF_OP_STX */
	default:
		dt_set_progerr(dtp, pgp, "unhandled instruction: %u",
		    opcode);
	}

	return (-1);
}

int
TypeInference::inferDIFO(dtrace_difo_t *difo)
{
	dfg_node *node = nullptr;
	int type = -1;


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

	/*
	 * If the symbol length is 0 and the symbol table is 0, we don't
	 * have any relocations to apply. In this case, we just return that
	 * no error occurred and leave the DIFO as it is.
	 */
	if (difo->dtdo_symtab == nullptr)
		return (0);

	if (pgp == nullptr)
		return (EDT_COMPILER);

	if (dtp == nullptr)
		return (EDT_COMPILER);

	difo->dtdo_types = (char **)malloc(sizeof(char *) * difo->dtdo_len);
	if (difo->dtdo_types == nullptr)
		dt_set_progerr(dtp, pgp, "failed to malloc dtdo_types");

	for (auto &node : dfg_nodes) {
		if (node.get() == r0node)
			continue;

		if (node->difo_buf() == nullptr)
			continue;

		if (node->difo_buf() != difo->dtdo_buf)
			continue;

		type = inferNode(node.get());
		assert(type == -1 ||
		    type == DIF_TYPE_CTF || type == DIF_TYPE_STRING ||
		    type == DIF_TYPE_NONE || type == DIF_TYPE_BOTTOM);

		if (type == -1)
			dt_set_progerr(dtp, pgp,
			    "failed to infer a type for %zu@%p\n",
			    node->uidx, node->difo);

		if (type == DIF_TYPE_CTF) {
			if (node->tf == nullptr)
				dt_set_progerr(dtp, pgp,
				    "%s(): typefile nullptr at %zu@%p\n", __func__,
				    node->uidx, node->difo);

			auto opt = node->tf->get_typename(node->ctfid);
			if (!opt.has_value())
				dt_set_progerr(dtp, pgp,
				    "inferDIFO(): failed at getting "
				    "type name %ld: %s (DIFO %p, node %zu)",
				    node->ctfid, node->tf->get_errmsg(),
				    node->difo, node->uidx);

			difo->dtdo_types[node->uidx] = strdup(
			    opt.value().c_str());
		} else if (type == DIF_TYPE_STRING)
			difo->dtdo_types[node->uidx] = strdup("string");
		else if (type == DIF_TYPE_NONE)
			difo->dtdo_types[node->uidx] = strdup("none");
		else if (type == DIF_TYPE_BOTTOM)
			difo->dtdo_types[node->uidx] = strdup("bottom");
		else
			difo->dtdo_types[node->uidx] = strdup("ERROR");
	}

	return (0);
}

}
