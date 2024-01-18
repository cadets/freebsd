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

#ifndef _DT_TYPEFILE_HH_
#define _DT_TYPEFILE_HH_

#include <dtrace.h>

#include <dt_module.h>

#ifndef __cplusplus
#error "File should only be included from C++"
#endif

#include <list>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dtrace {

template <typename T> using vec = std::vector<T>;
template <typename T> using uptr = std::unique_ptr<T>;
template <typename K, typename T> using umap = std::unordered_map<K, T>;
using std::pair;
using std::list;

struct struct_ctfinfo {
	vec<ctf_id_t> ctf_types;
	ssize_t current_offs = 0;
};

class typefile {
    private:
	umap<ctf_id_t, vec<ctf_id_t>> struct_info;

    public:
	dtrace_hdl_t *dtp = nullptr;
	dt_module_t *modhdl = nullptr;
	std::string modname = { 0 };

    public:
	typefile(dtrace_hdl_t *, dt_module_t *, std::string);
	typefile(dtrace_hdl_t *, dt_module_t *, const char *);
	typefile(dtrace_hdl_t *, dt_module_t *, char *);

	ctf_id_t get_ctfid(const char *) const;
	char *get_typename(ctf_id_t, char *, size_t) const;
	ctf_id_t get_reference(ctf_id_t) const;
	ssize_t get_size(ctf_id_t) const;
	const char *get_errmsg(void) const;
	ctf_file_t *get_membinfo(ctf_id_t, const char *, ctf_membinfo_t *) const;
	ctf_id_t get_kind(ctf_id_t) const;
	ctf_id_t resolve(ctf_id_t);
	int get_encoding(ctf_id_t, ctf_encoding_t *);
	int type_compat_with(ctf_id_t, const typefile *, ctf_id_t);
	vec<ctf_id_t> *build_struct(ctf_id_t);
	ctf_id_t memb_ctfid(void *);
	ctf_file_t *get_ctfp(void);
	ctf_arinfo_t *get_array_info(ctf_id_t);

	const std::string &name() const;
	const std::optional<std::string> get_typename(ctf_id_t) const;
};

extern list<uptr<typefile>> typefiles;

void dt_typefile_openall(dtrace_hdl_t *);
typefile *dt_typefile_first(void);
typefile *dt_typefile_kernel(void);
typefile *dt_typefile_D(void);
typefile *dt_typefile_mod(const char *);

constexpr typefile *
v2tf(void *tf)
{

	return (static_cast<typefile *>(tf));
}

};

#endif
