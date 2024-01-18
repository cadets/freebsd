/*-
 * Copyright (c) 2021 Domagoj Stolfa
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
#include <dt_list.h>
#include <dt_linker_subr.hh>
#include <dt_basic_block.hh>
#include <dt_dfg.hh>
#include <dt_typefile.hh>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include <dt_typing_helpers.hh>

namespace dtrace {

ctf_id_t
dt_type_strip_ref(typefile *tf, ctf_id_t &orig_id, size_t &n_stars)
{
	ctf_id_t kind;
	ctf_id_t id;
	size_t n_redirects;

	kind = tf->get_kind(orig_id);
	n_stars = 0;

	if (kind != CTF_K_TYPEDEF && kind != CTF_K_POINTER &&
	    kind != CTF_K_ARRAY)
		return (kind);

	id = orig_id;
	n_redirects = 0;

again:
	while (kind == CTF_K_TYPEDEF || kind == CTF_K_POINTER) {
		id = tf->get_reference(id);
		if (id == CTF_ERR) {
			fprintf(stderr,
			    "dt_typefile_reference() failed with: %s\n",
			    tf->get_errmsg());
			return (CTF_ERR);
		}

		if (kind == CTF_K_POINTER)
			n_redirects++;

		kind = tf->get_kind(id);
	}

	assert(kind != CTF_K_TYPEDEF && kind != CTF_K_POINTER);
	if (kind == CTF_K_ARRAY) {
		ctf_arinfo_t *ai;

		ai = tf->get_array_info(id);
		if (ai == nullptr)
			return (CTF_ERR);

		id = ai->ctr_contents;
		free(ai);

		n_redirects++;
		kind = tf->get_kind(id); /* update our kind */
		goto again;
	}

	n_stars = n_redirects;
	orig_id = id;
	return (kind);
}

ctf_id_t
dt_type_strip_typedef(typefile *tf, ctf_id_t *orig_id)
{
	ctf_id_t kind;
	ctf_id_t id;

	assert(orig_id != nullptr);

	kind = tf->get_kind(*orig_id);

	if (kind != CTF_K_TYPEDEF)
		return (kind);

	id = *orig_id;

	while (kind == CTF_K_TYPEDEF) {
		id = tf->get_reference(id);
		if (id == CTF_ERR) {
			fprintf(stderr,
			    "dt_typefile_reference() failed with: %s\n",
			    tf->get_errmsg());
			return (CTF_ERR);
		}

		kind = tf->get_kind(id);
	}

	assert(kind != CTF_K_TYPEDEF);
	*orig_id = id;

	return (kind);
}

static int
_dt_ctf_type_compare(uset<std::string> &processed_typenames, typefile *_tf1,
    ctf_id_t _id1, typefile *_tf2, ctf_id_t _id2)
{
	typefile *tf1, *tf2;
	size_t n_stars1, n_stars2;
	ctf_id_t id1, id2, kind1, kind2, tmp, memb1, memb2;
	std::string type1_name, type2_name, memb1_name, memb2_name;

	assert(_tf1 != nullptr);
	assert(_tf2 != nullptr);

	/*
	 * If we're comparing the same type, it's just equal.
	 */
	if (_tf1 == _tf2 && _id1 == _id2)
		return (0);

	kind1 = dt_type_strip_ref(_tf1, id1, n_stars1);
	kind2 = dt_type_strip_ref(_tf2, id2, n_stars2);

	assert(kind1 != CTF_K_UNKNOWN);
	assert(kind2 != CTF_K_UNKNOWN);

	assert(kind1 != CTF_K_FUNCTION);
	assert(kind2 != CTF_K_FUNCTION);

	assert(kind1 != CTF_K_FLOAT);
	assert(kind2 != CTF_K_FLOAT);

	assert(kind1 < CTF_K_MAX);
	assert(kind2 < CTF_K_MAX);

	tf1 = kind1 == CTF_K_STRUCT ? _tf1 : _tf2;
	tf2 = kind1 == CTF_K_STRUCT ? _tf2 : _tf1;
	id1 = kind1 == CTF_K_STRUCT ? _id1 : _id2;
	id2 = kind1 == CTF_K_STRUCT ? _id2 : _id1;

	tmp = kind1;
	kind1 = tmp == CTF_K_STRUCT ? tmp : kind2;
	kind2 = tmp == CTF_K_STRUCT ? kind2 : tmp;

	auto opt = tf1->get_typename(id1);
	if (!opt.has_value()) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    tf1->get_errmsg());
		return (-1);
	}

	type1_name = std::move(opt.value());
	opt = tf2->get_typename(id2);
	if (!opt.has_value()) {
		fprintf(stderr, "dt_typefile_typename() failed: %s\n",
		    tf2->get_errmsg());
		return (-1);
	}

	type2_name = std::move(opt.value());

	/*
	 * Give integers some leeway.
	 */
	if (kind1 == CTF_K_INTEGER && kind2 == CTF_K_INTEGER) {
		if (tf1->type_compat_with(id1, tf2, id2) == 0) {
			fprintf(stderr,
			    "%s(): %s and %s are incompatible integers\n",
			    __func__, type1_name.c_str(), type2_name.c_str());
			return (-1);
		}

		return (0);
	}

	/*
	 * Names must match
	 */
	if (type1_name != type2_name) {
		fprintf(stderr, "%s(): comparison not possible: %s != %s\n",
		    __func__, type1_name.c_str(), type2_name.c_str());
		return (-1);
	}

	if (kind1 == CTF_K_UNION || kind1 == CTF_K_ENUM ||
	    kind1 == CTF_K_FORWARD) {
		if (tf1->type_compat_with(id1, tf2, id2) == 0) {
			fprintf(stderr,
			    "dt_typefile_compat(): %s is not "
			    "compatible with %s\n",
			    type1_name.c_str(), type2_name.c_str());
			return (-1);
		}

		return (0);
	}

	if (kind1 == CTF_K_STRUCT) {
		auto *s1 = tf1->build_struct(id1);
		if (s1 == nullptr) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    tf1->name().c_str(), type1_name.c_str(),
			    tf1->get_errmsg());
			return (-1);
		}

		auto *s2 = tf2->build_struct(id2);
		if (s2 == nullptr) {
			fprintf(stderr,
			    "dt_typefile_buildup_struct(%s) "
			    "failed for %s: %s\n",
			    tf2->name().c_str(), type2_name.c_str(),
			    tf2->get_errmsg());
			return (-1);
		}

		vec<ctf_id_t>::iterator it1, it2;
		/*
		 * Go over each member and ensure that if both exist, they are
		 * pointwise equal. We don't accept *any* variety between them.
		 */
		for (it1 = s1->begin(), it2 = s2->begin();
		     it1 != s1->end() && it2 != s2->end(); ++it1, ++it2) {
			memb1 = *it1;
			memb2 = *it2;

			opt = tf1->get_typename(memb1);
			if (!opt.has_value()) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    tf1->get_errmsg());
				return (-1);
			}

			memb1_name = std::move(opt.value());
			opt = tf2->get_typename(memb2);
			if (!opt.has_value()) {
				fprintf(stderr,
				    "dt_typefile_typename() failed: %s\n",
				    tf2->get_errmsg());
				return (-1);
			}

			memb2_name = std::move(opt.value());

			if (processed_typenames.contains(memb1_name))
				continue;

			if (_dt_ctf_type_compare(processed_typenames, tf1,
			    memb1, tf2, memb2)) {
				fprintf(stderr,
				    "comparison between %s and %s failed\n",
				    memb1_name.c_str(), memb2_name.c_str());
				return (-1);
			}

			processed_typenames.insert(memb1_name);
		}

		assert(it1 == s1->end() || it2 == s2->end());

		if (memb1 != memb2) {
			fprintf(stderr,
			    "structures %s (%s) and %s (%s) "
			    "don't match\n",
			    type1_name.c_str(), tf1->name().c_str(),
			    type2_name.c_str(), tf2->name().c_str());
			return (-1);
		}
	}

	return (0);
}

int
dt_ctf_type_compare(typefile *tf1, ctf_id_t id1,
    typefile *tf2, ctf_id_t id2)
{
	uset<std::string> processed_typenames;
	return (_dt_ctf_type_compare(processed_typenames, tf1, id1, tf2, id2));
}

static int
dt_is_void(std::string &t)
{

	return (t == "void *" || t == "const void *");
}

int
dt_typecheck_string(dtrace_hdl_t *dtp, int t1, int t2, ctf_id_t c1, ctf_id_t c2,
    typefile *tf1, typefile *tf2)
{
	if (t1 == DIF_TYPE_STRING && t2 == DIF_TYPE_CTF) {
		dt_module_t *mod = tf2->modhdl;
		return (c2 == dtp->dt_type_str && mod == dtp->dt_ddefs);
	} else if (t1 == DIF_TYPE_CTF && t2 == DIF_TYPE_STRING) {
		return (dt_typecheck_string(dtp, t2, t1, c2, c1, tf2, tf1));
	}

	return (t1 == DIF_TYPE_STRING && t2 == DIF_TYPE_STRING);
}

int
dt_typecheck_stringiv(dtrace_hdl_t *dtp, dfg_node *n, dtrace_difv_t *dv)
{

	return (dt_typecheck_string(dtp, n->d_type, dv->dtdv_type.dtdt_kind,
	    n->ctfid, dv->dtdv_ctfid, n->tf, v2tf(dv->dtdv_tf)));
}

int
dt_typecheck_stringii(dtrace_hdl_t *dtp, dfg_node *n1, dfg_node *n2)
{

	return (dt_typecheck_string(dtp, n1->d_type, n2->d_type,
	    n1->ctfid, n2->ctfid, n1->tf, n2->tf));
}

int
dt_type_subtype(typefile *tf1, ctf_id_t id1, typefile *tf2,
    ctf_id_t id2, int *which)
{
	ctf_id_t kind1, kind2;
	size_t n_stars1, n_stars2;
	uint32_t size1, size2;
	int isvoid1, isvoid2;
	char buf[4096];
	std::string r1_type_name, r2_type_name, type1_name, type2_name,
	    memb1_name, memb2_name;
	ctf_id_t s1, s2, memb1, memb2;

	*which = SUBTYPE_NONE;

	assert(tf1 != nullptr);
	assert(tf2 != nullptr);

	auto opt = tf1->get_typename(id1);
	if (!opt.has_value()) {
		return (-1);
	}

	type1_name = std::move(opt.value());
	opt = tf2->get_typename(id2);
	if (!opt.has_value()) {
		return (-1);
	}

	type2_name = std::move(opt.value());
	isvoid1 = dt_is_void(type1_name);
	isvoid2 = dt_is_void(type2_name);

	if (isvoid1 && isvoid2) {
		*which = SUBTYPE_EQUAL;
		return (0);
	} else if (isvoid1) {
		*which = SUBTYPE_FST;
		return (0);
	} else if (isvoid2) {
		*which = SUBTYPE_SND;
		return (0);
	}

	kind1 = dt_type_strip_ref(tf1, id1, n_stars1);
	kind2 = dt_type_strip_ref(tf2, id2, n_stars2);

	/*
	 * In case number of stars in a pointer didn't match.
	 */
	if (n_stars1 != n_stars2) {
		fprintf(stderr,
		    "mismatched pointer %s != %s "
		    "(%zu stars != %zu stars)\n",
		    type1_name.c_str(), type2_name.c_str(), n_stars1, n_stars2);
		return (-1);
	}

	/*
	 * We don't want bogus values, functions or floats here.
	 */
	assert(kind1 != CTF_K_UNKNOWN);
	assert(kind2 != CTF_K_UNKNOWN);

	assert(kind1 != CTF_K_FUNCTION);
	assert(kind2 != CTF_K_FUNCTION);

	assert(kind1 != CTF_K_FLOAT);
	assert(kind2 != CTF_K_FLOAT);

	assert(kind1 < CTF_K_MAX);
	assert(kind2 < CTF_K_MAX);

	/*
	 * For integers, we just want to check if they are compatible and then
	 * pick the one that is larger as the one to use for our storage.
	 */
	if (kind1 == CTF_K_INTEGER && kind2 == CTF_K_INTEGER) {
		ctf_encoding_t enc1, enc2;

		if (tf1->get_encoding(id1, &enc1) != 0) {
			fprintf(stderr,
			    "dt_type_subtype(): failed getting encoding "
			    "with %s: %s\n",
			    tf1->name().c_str(), tf1->get_errmsg());
			return (-1);
		}

		if (tf2->get_encoding(id2, &enc2) != 0) {
			fprintf(stderr,
			    "dt_type_subtype(): failed getting encoding "
			    "with %s: %s\n",
			    tf2->name().c_str(), tf2->get_errmsg());
			return (-1);
		}

		size1 = tf1->get_size(id1);
		size2 = tf2->get_size(id2);

#if 0
		if (enc1.cte_format != enc2.cte_format && size1 == size2) {
			fprintf(stderr,
			    "dt_type_subtype(): both arguments types "
			    "need to have same signedness\n");
			return (-1);
		}
#endif

		if (size1 == size2)
			*which = SUBTYPE_EQUAL;
		else
			*which = size1 > size2 ? SUBTYPE_FST : SUBTYPE_SND;

		return (0);
	}

	/*
	 * We require that arrays are fully compatible
	 */
	if (kind1 == CTF_K_ARRAY && kind2 == CTF_K_ARRAY) {
		if (dt_ctf_type_compare(tf1, id1, tf2, id2))
			return (-1);

		*which = SUBTYPE_EQUAL;
		return (0);
	}

	if (tf1->get_typename(id1, buf, sizeof(buf)) != (char *)buf) {
		fprintf(stderr, "typefile::get_typename() failed: %s\n",
		    tf1->get_errmsg());
		return (-1);
	}

	r1_type_name = std::string(buf);

	if (tf2->get_typename(id2, buf, sizeof(buf)) != (char *)buf) {
		fprintf(stderr, "typefile::get_typename() failed: %s\n",
		    tf2->get_errmsg());
		return (-1);
	}

	r2_type_name = std::string(buf);

	/*
	 * Since this is C, we do a comparison by name first. If the names don't
	 * match identically, we aren't really interested.
	 *
	 * Note that this is not really a requirement and we could require a
	 * definition of equivalence defined by a bijection which is far more
	 * relaxed, but for now we require that the name matches. This is easily
	 * removed later.
	 */
	if (r1_type_name != r2_type_name) {
		fprintf(stderr, "%s(): subtyping not possible: %s != %s\n",
		    __func__, type1_name.c_str(), type2_name.c_str());
		return (-1);
	}

	size1 = tf1->get_size(id1);
	size2 = tf2->get_size(id2);

	/*
	 * We should never have gotten to this point if we were going to get
	 * CTF_ERR.
	 */
	assert(size1 != CTF_ERR);
	assert(size2 != CTF_ERR);

	if (kind1 == CTF_K_STRUCT) {
		/*
		 * We have a few conditions for subtyping of structs.
		 *
		 * s1 is a subtype of s2 iff:
		 *  (1) sizeof(s1) <= sizeof(s2)
		 *  (2) s1 is a slice of s2 (s1 = s2 up to a point, but s2 has
		 *                           more stuff afterwards)
		 *
		 * We could loosen this restriction quite a bit, but for now
		 * this is sufficient.
		 */

		auto *s1 = tf1->build_struct(id1);
		if (s1 == nullptr) {
			fprintf(stderr,
			    "build up struct %s failed for %s: %s\n",
			    type1_name.c_str(), tf1->name().c_str(),
			    tf1->get_errmsg());
			return (-1);
		}

		auto *s2 = tf2->build_struct(id2);
		if (s2 == nullptr) {
			fprintf(stderr,
			    "build up struct %s failed for %s: %s\n",
			    type2_name.c_str(), tf2->name().c_str(),
			    tf2->get_errmsg());
			return (-1);
		}

		vec<ctf_id_t>::iterator it1, it2;
		/*
		 * Go over each member and ensure that if both exist, they are
		 * pointwise equal. We don't accept *any* variety between them.
		 */
		for (it1 = s1->begin(), it2 = s2->begin();
		     it1 != s1->end() && it2 != s2->end(); ++it1, ++it2) {
			memb1 = *it1;
			memb2 = *it2;

			auto opt = tf1->get_typename(memb1);
			if (!opt.has_value()) {
				return (-1);
			}

			memb1_name = std::move(opt.value());
			opt = tf2->get_typename(memb2);
			if (!opt.has_value()) {
				return (-1);
			}

			memb2_name = std::move(opt.value());
			if (dt_ctf_type_compare(tf1, memb1, tf2, memb2)) {
				fprintf(stderr,
				    "comparison between %s and %s failed\n",
				    memb1_name.c_str(), memb2_name.c_str());
				return (-1);
			}
		}

		assert(it1 == s1->end() || it2 == s2->end());
		if (it1 == s1->end() && it2 != s2->end())
			*which = SUBTYPE_FST;
		else if (it1 != s1->end() && it2 == s2->end())
			*which = SUBTYPE_SND;
		else
			*which = SUBTYPE_EQUAL;

		return (0);
	} else if (kind1 == CTF_K_UNION || kind1 == CTF_K_ENUM ||
	    kind1 == CTF_K_FORWARD) {
		/*
		 * It doesn't really make sense to support different unions or
		 * enum types. We only check pointwise equality.
		 */
		if (dt_ctf_type_compare(tf1, id1, tf2, id2))
			return (-1);

		*which = SUBTYPE_EQUAL;
		return (0);
	}

	fprintf(stderr, "unknown typing error (%s != %s)\n", type1_name.c_str(),
	    type2_name.c_str());
	return (-1);
}

/*
 * dt_get_class() takes in a buffer containing the type name and returns
 * the internal DTrace class it belongs to (DTC_INT, DTC_BOTTOM, DTC_STRUCT).
 */
int
dt_get_class(typefile *tf, ctf_id_t id, int follow)
{
	ctf_id_t ot, k, new_id;
	int typeclass;
	char buf[DT_TYPE_NAMELEN];
	typefile *typef;

	ot = -1;
	k = 0;

	/* ignore any errors here. */
	tf->get_typename(id, buf, sizeof(buf));

	do {

		if ((k = tf->get_kind(id)) == CTF_ERR)
			return (DTC_BOTTOM);

		if (id == ot)
			break;

		ot = id;
	} while (((id = tf->get_reference(id)) != CTF_ERR));

	if (k == CTF_K_INTEGER)
		return (DTC_INT);

	if (k == CTF_K_STRUCT)
		return (DTC_STRUCT);

	if (k == CTF_K_UNION)
		return (DTC_UNION);

	if (k == CTF_K_ENUM)
		return (DTC_ENUM);

	if (k == CTF_K_ARRAY) {
		ctf_arinfo_t *ai;
		ctf_id_t src_type;

		ai = tf->get_array_info(ot);
		if (ai == nullptr)
			return (DTC_BOTTOM);

		src_type = ai->ctr_contents;
		free(ai);

		return (dt_get_class(tf, src_type, 1));
	}

	if (k == CTF_K_FORWARD) {
		ctf_file_t *parent, *current;
		if (!follow)
			return (DTC_FORWARD);

		parent = ctf_parent_file(tf->get_ctfp());
		if (parent == nullptr)
			return (DTC_FORWARD);

		if (id == CTF_ERR)
			id = ot;

		typef = nullptr;

		/* follow the list of typefiles until we find the right one */
		for (auto &t : typefiles) {
			current = t->get_ctfp();
			if (current == parent) {
				typef = t.get();
				break;
			}

			if (typeclass == DTC_INT || typeclass == DTC_STRUCT)
				return (typeclass);
		}

		if (typef == nullptr)
			return (DTC_FORWARD);

		new_id = typef->get_ctfid(buf);
		if (new_id == CTF_ERR)
			return (DTC_FORWARD);
		typeclass = dt_get_class(typef, new_id, 0);
		return (typeclass);
	}

	return (DTC_BOTTOM);
}

ctf_membinfo_t *
dt_mip_from_sym(dfg_node *n)
{
	ctf_membinfo_t *mip;
	int c;
	char buf[DT_TYPE_NAMELEN] = { 0 };
	ctf_id_t type;
	ctf_id_t kind;
	dtrace_difo_t *difo;

	if (n == nullptr)
		return (nullptr);

	/*
	 * If there is no symbol here, we can't do anything.
	 */
	if (n->sym == nullptr)
		return (nullptr);

	if (n->difo == nullptr)
		return (nullptr);

	difo = n->difo;

	/*
	 * sym in range(symtab)
	 */
	if ((uintptr_t)n->sym >=
	    ((uintptr_t)difo->dtdo_symtab) + difo->dtdo_symlen)
		return (nullptr);

	c = dt_get_class(n->tf, n->ctfid, 1);
	if (c != DTC_STRUCT && c != DTC_FORWARD) {
		return (nullptr);
	}

	/*
	 * Figure out t2 = type_at(t1, symname)
	 */
	mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
	if (mip == nullptr)
		return (nullptr);

	memset(mip, 0, sizeof(ctf_membinfo_t));

	kind = n->tf->get_kind(n->ctfid);
	if (kind == CTF_K_POINTER || kind == CTF_K_VOLATILE ||
	    kind == CTF_K_TYPEDEF || kind == CTF_K_RESTRICT ||
	    kind == CTF_K_CONST)
		/*
		 * Get the non-pointer type. This should NEVER fail.
		 */
		type = n->tf->get_reference(n->ctfid);
	else
		type = n->ctfid;

	assert(type != CTF_ERR);

	if (n->tf->get_membinfo(type, n->sym, mip) == 0) {
		free(mip);
		return (nullptr);
	}

	return (mip);
}

/*
 * dt_type_compare() takes in two IFG nodes and "compares" their types.
 * Specifically, BOTTOM is the smallest element and no matter what it is
 * compared to, it is smaller than it (reflexivity applies). By convention,
 * we check dr1 for a BOTTOM type first and return dn2 if dr1 is BOTTOM
 * regardless of what dn2 is (could be BOTTOM). Both STRUCT and STRING are
 * considered to be greater than INT (because in DIF when we are adding an
 * integer onto a struct pointer or a string, we still expect to use it as
 * a string or a structure, rather than as a number).
 */
int
dt_type_compare(dfg_node *dn1, dfg_node *dn2)
{
	char buf[DT_TYPE_NAMELEN] = {0};
	std::string t1, t2;
	int class1, class2;

	class1 = 0;
	class2 = 0;

	if (dn1->d_type == DIF_TYPE_BOTTOM &&
	    dn2->d_type == DIF_TYPE_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp, "both types are bottom");

	assert(dn1->d_type != DIF_TYPE_BOTTOM ||
	    dn2->d_type != DIF_TYPE_BOTTOM);

	if (dn1->d_type == DIF_TYPE_BOTTOM)
		return (2);

	if (dn2->d_type == DIF_TYPE_BOTTOM)
		return (1);

	assert(dn1->d_type != DIF_TYPE_NONE);
	assert(dn2->d_type != DIF_TYPE_NONE);

	if (dn1->d_type == DIF_TYPE_CTF) {
		auto opt = dn1->tf->get_typename(dn1->ctfid);
		if (!opt.has_value()) {
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_type_compare(): failed at getting type "
			    "name %ld: %s",
			    dn1->ctfid, dn1->tf->get_errmsg());
		}

		t1 = std::move(opt.value());
	}

	if (dn2->d_type == DIF_TYPE_CTF) {
		auto opt = dn2->tf->get_typename(dn2->ctfid);
		if (!opt.has_value()) {
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_type_compare(): failed at getting type "
			    "name %ld: %s",
			    dn2->ctfid, dn2->tf->get_errmsg());
		}

		t2 = std::move(opt.value());
	}

	class1 = dn1->d_type == DIF_TYPE_CTF ?
	    dt_get_class(dn1->tf, dn1->ctfid, 1) :
	    DTC_STRING;
	class2 = dn2->d_type == DIF_TYPE_CTF ?
	    dt_get_class(dn2->tf, dn2->ctfid, 1) :
	    DTC_STRING;

	if (class1 == DTC_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp,
		    "dt_type_compare(): class1 is bottom because of %s",
		    t1.c_str());

	if (class2 == DTC_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp,
		    "dt_type_compare(): class2 is bottom because of %s",
		    t2.c_str());

	if (class1 == DTC_STRING && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_STRUCT && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_UNION && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_FORWARD && class2 == DTC_INT)
		return (1);

	if ((class1 == DTC_ENUM && class2 == DTC_ENUM) ||
	    (class1 == DTC_INT && class2 == DTC_ENUM)  ||
	    (class1 == DTC_ENUM && class2 == DTC_INT))
		return (1);

	if (class1 == DTC_INT &&
	    (class2 == DTC_STRUCT || class2 == DTC_STRING ||
	    class2 == DTC_FORWARD || class2 == DTC_UNION))
		return (2);

	/*
	 * If the types are of the same class, we return the the first type
	 * by convention.
	 */
	if (class1 == DTC_INT && class2 == DTC_INT)
		return (1);

	return (-1);
}

typefile *
dt_get_typename_tfcheck(dfg_node *n, typefile **tfs, size_t ntfs,
    char *buf, size_t bufsize, const char *loc)
{
	typefile *tf;
	size_t i;

	for (i = 0; i < ntfs; i++) {
		tf = tfs[i];

		if (n->tf == tf)
			break;
	}

	assert(i <= ntfs);

	if (i == ntfs)
		dt_set_progerr(g_dtp, g_pgp,
		    "%s: node %zu' could not find typefile '%s'", loc,
		    n->uidx, n->tf->name().c_str());

	if (n->tf->get_typename(n->ctfid, buf, bufsize) != buf)
		dt_set_progerr(g_dtp, g_pgp,
		    "%s: (%zu) failed getting type name %ld: %s", loc,
		    n->uidx, n->ctfid, n->tf->get_errmsg());

	return (tf);
}

struct membinfo_helper {
	dtrace_hdl_t *dtp;
	ctf_file_t *ctfp;
	ctf_membinfo_t *mip;
	uint64_t offs;
	ctf_id_t ctfid;
};

static int
dt_find_memboffs(const char *name, ctf_id_t ctfid, ulong_t off, void *arg)
{
	membinfo_helper *mh = (membinfo_helper *)arg;

	/* invalid argument, return an error */
	if (arg == nullptr)
		return (-1);

	/* we already found our member, simply return. */
	if (mh->mip != nullptr)
		return (0);

	/* if not matching, simply continue searching. */
	if (off / NBBY != mh->offs)
		return (0);

	/*
	 * We now know we have a matching offset. Get the mip and populate our
	 * struct.
	 */
	mh->mip = (ctf_membinfo_t *)malloc(sizeof(ctf_membinfo_t));
	if (mh->mip == nullptr)
		return (-1);

	memset(mh->mip, 0, sizeof(ctf_membinfo_t));
	if (ctf_member_info(mh->ctfp, mh->ctfid, name, mh->mip) == CTF_ERR)
		return (-1);

	/*
	 * We now have the membinfo filled in, so we just return 0.
	 */
	return (0);
}

ctf_membinfo_t *
dt_mip_by_offset(dtrace_hdl_t *dtp, typefile *tf, ctf_id_t ctfid,
    uint64_t offs)
{
	ctf_file_t *ctfp;
	membinfo_helper mh = { 0 };

	ctfp = tf->get_ctfp();

	mh.offs = offs;
	mh.ctfp = ctfp;
	mh.dtp = dtp;
	mh.ctfid = ctfid;

	if (ctf_member_iter(mh.ctfp, ctfid, dt_find_memboffs, &mh) == -1)
		return (nullptr);

	return (mh.mip);
}

ctf_id_t
dt_autoresolve_ctfid(const char *mod, const char *resolved_type,
    typefile **tfp)
{
	typefile *tf;
	ctf_id_t ctfid;

	tf = nullptr;
	ctfid = CTF_ERR;

	/*
	 * Try by module first.
	 */
	if (strcmp(mod, "freebsd") == 0)
		tf = dt_typefile_kernel();
	else
		tf = dt_typefile_mod(mod);

	if (tf != nullptr)
		ctfid = tf->get_ctfid(resolved_type);

	if (tf == nullptr || ctfid == CTF_ERR) {
		/*
		 * FIXME: This probably doesn't match what libdtrace currently
		 * does with modules.
		 */
		for (auto &t : typefiles) {
			ctfid = t->get_ctfid(resolved_type);
			if (ctfid != CTF_ERR) {
				tf = t.get();
				break;
			}
		}
	}

	*tfp = tf;
	return (ctfid);
}

}