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

#include <sys/types.h>
#include <sys/dtrace.h>

#include <assert.h>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_impl.h>
#include <dt_linker_subr.hh>
#include <dt_list.h>
#include <dt_program.h>
#include <dt_typefile.hh>
#include <dt_typing.hh>
#include <dt_typing_helpers.hh>
#include <dtrace.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

namespace dtrace {

using std::list;
static list<uptr<node_vec>> var_nodevecs;

/*
 * dt_var_stack_typecheck() ensures that all the stacks at variable use
 * and definition site across all branches are consistent in their types.
 * Moreover, ensure that if we already have a variable in our varlist that
 * corresponds to the variable we are currently inferring/checking the type
 * of, ensure that the types there are consistent as well.
 */
int
dt_var_stack_typecheck(dfg_node *n, dfg_node *dr1, dtrace_difv_t *dif_var)
{
	dfg_node *var_stacknode, *node;
	std::string var_type, type;
	char buf[4096] = {0};

	if (dr1 == nullptr && dif_var == nullptr) {
		fprintf(stderr, "both dr1 and dif_var are nullptr");
		return (-1);
	}

	/*
	 * If there was nothing to typecheck above, then we simply create a new
	 * stack for the variable using the data from what we were comparing it
	 * to and move on.
	 */
	if (dif_var->dtdv_stack == nullptr) {
		var_nodevecs.push_back(std::make_unique<node_vec>());
		auto var_nodeset = var_nodevecs.back().get();
		dif_var->dtdv_stack = (void *)var_nodeset;
		if (dif_var->dtdv_stack == nullptr)
			dt_set_progerr(g_dtp, g_pgp, "failed to malloc dtdv_stack");

		if (n->stacks.size() == 0)
			dt_set_progerr(g_dtp, g_pgp, "sl is nullptr, nonsense.");

		for (auto node : n->stacks[0].nodes_on_stack) {
			var_nodeset->push_back(node);
		}

		return (0);
	} else if (dr1 == nullptr)
		return (0);

	/*
	 * In the case that we _do_ have a variable in our varlist, we
	 * check that the types of the inside DIFO definition and the varlist
	 * definition are consistent.
	 */
	for (auto &stack : n->stacks) {
		node_vec::iterator ni;
		node_vec::iterator vi;
		node_vec *var_stack = (node_vec *)dif_var->dtdv_stack;

		for (ni = stack.nodes_on_stack.begin(), vi = var_stack->begin();
		    ni != stack.nodes_on_stack.end() && vi != var_stack->end();
		    ++vi, ++ni) {
			node = *ni;
			var_stacknode = *vi;

			if (node->d_type != var_stacknode->d_type) {
				fprintf(stderr, "type mismatch in variable\n");
				return (-1);
			}

			if (node->tf != var_stacknode->tf) {
				fprintf(stderr, "typefile mismatch: %s != %s\n",
				    node->tf->name().c_str(),
				    var_stacknode->tf->name().c_str());
				return (-1);
			}

			if (node->d_type == DIF_TYPE_CTF) {
				auto opt = node->tf->get_typename(node->ctfid);
				if (!opt.has_value())
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting type name %ld: %s",
					    dr1->ctfid, node->tf->get_errmsg());

				type = std::move(opt.value());
				opt = var_stacknode->tf->get_typename(
				    var_stacknode->ctfid);
				if (!opt.has_value())
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting type name %ld: %s",
					    var_stacknode->ctfid,
					    var_stacknode->tf->get_errmsg());

				var_type = std::move(opt.value());
				if (var_stacknode->ctfid != node->ctfid) {
					fprintf(stderr, "type mismatch "
					    "in stgaa: %s != %s\n",
					    type.c_str(), var_type.c_str());
					return (-1);
				}
			}
		}
	}

	return (0);
}

/*
 * dt_typecheck_stack() ensures that everything on the stack across all branches
 * is consistent with its types.
 */
node_vec *
dt_typecheck_stack(dfg_node *n, vec<stackdata> &stacks, int *empty)
{
	node_vec *stack, *ostack;
	std::string type1, type2;

	*empty = 1;

	if (stacks.size() > 0)
		stack = &stacks.begin()->nodes_on_stack; // FIXME: hack
	for (auto it = stacks.begin(); it != stacks.end(); ++it) {
		*empty = 0;
		ostack = stack;
		stack = &it->nodes_on_stack;

		/*
		 * Infer types on the stack.
		 */
		for (auto n : *stack) {
			if (dt_infer_type(n) == -1)
				dt_set_progerr(g_dtp, g_pgp,
				    "%s(%p[%zu]): failed to infer "
				    "type for opcode %d at %zu (%p)\n",
				    __func__, n->difo, n->uidx,
				    n->get_instruction(), n->uidx, n->difo);
		}

		if (ostack == nullptr)
			continue;

		for (auto ni = stack->begin(), oni = ostack->begin();
		     ni != stack->end() && oni != stack->end(); ++ni, ++oni) {
			auto n = *ni;
			auto on = *oni;

			if (n->d_type != on->d_type) {
				fprintf(stderr,
				    "%s(%p[%zu]): stack type "
				    "mismatch at %zu and %zu (%p): %d != %d\n",
				    __func__, n->difo, n->uidx, n->uidx,
				    on->uidx, n->difo, n->d_type, on->d_type);

				return (nullptr);
			}

			/*
			 * TODO(dstolfa, important): We don't really want to
			 * compare by ctfid anymore because when we compare
			 * types across modules, we will have differing ctfids.
			 * We instead need to compare this via strings or some
			 * other mechanism...
			 */
			if (n->ctfid != on->ctfid) {
				type1 = n->tf->get_typename(n->ctfid)
				    .value_or("ERROR");
				type2 = on->tf->get_typename(on->ctfid)
				    .value_or("ERROR");
				fprintf(stderr,
				    "%s(%p[%zu]): stack ctf type "
				    "mismatch at %zu and %zu (%p): %s != %s\n",
				    __func__, n->difo, n->uidx, n->uidx,
				    on->uidx, n->difo, type1.c_str(),
				    type2.c_str());

				return (nullptr);
			}

			if (n->sym || on->sym) {
				fprintf(stderr,
				    "%s(%p[%zu]): symbol found "
				    "on stack at %zu (%p)\n",
				    __func__, n->difo, n->uidx,
				    n->sym ? n->uidx : on->uidx, n->difo);
				return (nullptr);
			}
		}
	}

	return (stack);
}

}