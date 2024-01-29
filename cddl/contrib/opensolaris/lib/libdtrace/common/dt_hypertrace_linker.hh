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

#ifndef _HYPERTRACE_LINKER_HH_
#define _HYPERTRACE_LINKER_HH_

#include <sys/dtrace.h>

#ifndef __cplusplus
#error "File should only be included from C++"
#endif

#include <dt_cxxdefs.hh>
#include <dtrace.h>

namespace dtrace {
class HyperTraceLinker {
    private:
	dtrace_hdl_t *dtp;
	dtrace_prog_t *pgp;

	DFGNode *r0node = nullptr;

    public:
	DFGList dfgNodes;
	Vec<UPtr<BasicBlock>> basicBlocks;
	Vec<UPtr<dtrace_difv_t>> varVector;

    private:
	void patchUsetxDefs(DFGNode *);
	int processDIFO(dtrace_actdesc_t *, dtrace_difo_t *, dtrace_ecbdesc_t *,
	    array<umap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &);
	void relocateDFGNode(DFGNode *, dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_difo_t *, dtrace_diftype_t *);
	void assembleProgram(dtrace_difo_t *,
	    array<umap<uint32_t, dtrace_diftype_t>, DIFV_NSCOPES> &);
	int relocateProgram(dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_difo_t *, dtrace_diftype_t *);
	void updateUsetxDefsInBB(dtrace_difo_t *, BasicBlock *, DFGNode *);
	void updateUsetxDefs(dtrace_difo_t *, BasicBlock *, DFGNode *);
	void inferUsetxDefs(dtrace_difo_t *);
	void relocateRetOrPush(DFGNode *, dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_diftype_t *);
	void relocatePush(DFGNode *, dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_diftype_t *);
	void relocateRet(DFGNode *, dtrace_actkind_t, dtrace_actdesc_t *,
	    dtrace_diftype_t *);
	void relocateUloadOrAdd(DFGNode *);
	void computebasicBlocks(dtrace_difo_t *);
	void computeCFG(dtrace_difo_t *);
	void insertVar(dtrace_difo_t *, uint16_t, uint8_t, uint8_t);
	void insertVar(dtrace_difv_t *);
	void populateVariablesFromDIFO(dtrace_difo_t *);
	void updateActiveVarRegs(uint8_t[DIF_DIR_NREGS], dtrace_difo_t *,
	    BasicBlock *, DFGList::iterator);
	bool updateNodesInBBForVar(dtrace_difo_t *, BasicBlock *, DFGNodeData &,
	    DFGList::iterator);
	int updateNodesInBBForStack(Vec<BasicBlock *> &, dtrace_difo_t *,
	    BasicBlock *, DFGList::iterator);
	int updateNodesInBBForReg(dtrace_difo_t *, BasicBlock *, uint8_t,
	    DFGList::iterator, int *);
	void updateDFG(dtrace_difo_t *, DFGNode *, DFGList::iterator);
	int computeDFG(dtrace_ecbdesc_t *, dtrace_difo_t *);

    public:
	HyperTraceLinker(dtrace_hdl_t *, dtrace_prog_t *);
	~HyperTraceLinker() = default;

	int link();
	const DFGNode *getR0Node() const { return (r0node); }
	Typefile *getTypenameChecked(DFGNode *, Vec<Typefile *> &, char *,
	    size_t, const std::string &);
	dtrace_difv_t *getVarFromVarVec(uint16_t, int, int);
};
}

#endif /* _HYPERTRACE_LINKER_HH_ */
