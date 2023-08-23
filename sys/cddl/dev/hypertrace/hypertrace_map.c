/*-
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
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

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>

#include "hypertrace.h"

#define MAP_HOSTID     0
#define MAP_BUCKETSIZE 4096

static void
syncfn(void *arg __unused)
{
}

static void
sync(void)
{

	smp_rendezvous_cpus(all_cpus, smp_no_rendezvous_barrier, syncfn,
	    smp_no_rendezvous_barrier, NULL);
}

hypertrace_map_t *
map_init(void)
{
	hypertrace_map_t *map;

	map = kmem_zalloc(sizeof(hypertrace_map_t), KM_SLEEP);
	mutex_init(&map->mtx, "hypertrace map state", MUTEX_DEFAULT, NULL);
	return (map);
}

void
map_teardown(hypertrace_map_t *map)
{
	size_t i, j;
	hypertrace_probe_t **probes, *probe;

	if (map == NULL)
		return;

	/*
	 * Go over all of the buckets in a map and free each probe, followed by
	 * freeing the probe table itself. At the end, free the map.
	 */
	mutex_enter(&map->mtx);
	for (i = 0; i < HYPERTRACE_MAX_VMS; i++) {
		if (map->probes[i] == NULL)
			continue;

		for (j = 0; j < map->nprobes[i]; j++) {
			probe = map->probes[i][j];
			if (probe == NULL)
				continue;

			map->probes[i][j] = NULL;
			kmem_free(probe, sizeof(hypertrace_probe_t));
		}

		probes = map->probes[i];
		map->nprobes[i] = 0;
		map->probes[i] = NULL;
		sync();

		kmem_free(probes, sizeof(hypertrace_probe_t *));
	}

	mutex_exit(&map->mtx);
	kmem_free(map, sizeof(hypertrace_map_t));
}

void
map_insert(hypertrace_map_t *map, hypertrace_probe_t *probe)
{
	size_t nprobes;
	hypertrace_probe_t **new_probes;
	dtrace_id_t id;
	uint16_t vmid;

	vmid = probe->htpb_vmid;
	nprobes = map->nprobes[vmid];

	id = probe->htpb_id;

	mutex_enter(&map->mtx);
	if (id - 1 >= nprobes && id - 1 <= DTRACE_SENSIBLE_PROBELIMIT) {
		size_t nsize;
		size_t osize;

		osize = nprobes * sizeof(dtrace_probe_t *);
		nsize = dtrace_nextpow2(id) * sizeof(dtrace_probe_t *);

		ASSERT((nsize / sizeof(dtrace_probe_t *)) > id - 1);
		new_probes = kmem_zalloc(nsize, KM_SLEEP);

		if (map->probes[vmid] == NULL) {
			ASSERT(osize == 0);
			map->probes[vmid] = new_probes;
			map->nprobes[vmid] = nsize / sizeof(dtrace_probe_t *);
		} else {
			hypertrace_probe_t **oprobes = map->probes[vmid];

			memcpy(new_probes, oprobes, osize);
			map->probes[vmid] = new_probes;
			sync();

			kmem_free(oprobes, osize);
			map->nprobes[vmid] = nsize / sizeof(dtrace_probe_t *);
		}

		ASSERT(id - 1 < map->nprobes[vmid]);
	}

	ASSERT(map->probes[vmid][id - 1] == NULL);
	map->probes[vmid][id - 1] = probe;
	mutex_exit(&map->mtx);
}

/*
 * Safe getter for an element.
 */
hypertrace_probe_t *
map_get(hypertrace_map_t *map, uint16_t vmid, dtrace_id_t id)
{
	if (map == NULL || map->probes[vmid] == NULL || map->nprobes[vmid] <= id)
		return (NULL);

	return (map->probes[vmid][id - 1]);
}

void
map_rm(hypertrace_map_t *map, hypertrace_probe_t *probe)
{
	if (map == NULL || map->probes[probe->htpb_vmid] == NULL)
		return;

	if (map->nprobes[probe->htpb_vmid] <= probe->htpb_id)
		panic("%u: nprobes = %zu, probe id = %d", probe->htpb_vmid,
		    map->nprobes[probe->htpb_vmid], probe->htpb_id);

	if (map->probes[probe->htpb_vmid][probe->htpb_id - 1] == NULL)
		panic("Attempting to remove a NULL entry: %u, %d\n",
		    probe->htpb_vmid, probe->htpb_id);

	mutex_enter(&map->mtx);
	map->probes[probe->htpb_vmid][probe->htpb_id - 1] = NULL;
	mutex_exit(&map->mtx);
}

int
map_count(hypertrace_map_t *map, uint16_t vmid, size_t *count)
{
	size_t nprobes, i;
	hypertrace_probe_t **probes;

	if (map == NULL || vmid >= HYPERTRACE_MAX_VMS)
		return (EINVAL);

	mutex_enter(&map->mtx);
	/* vmid == MAP_HOSTID means all probes */
	if (vmid == MAP_HOSTID) {
		nprobes = 0;

		for (i = 0; i < HYPERTRACE_MAX_VMS; i++) {
			if (map->probes[i] == NULL)
				continue;
			nprobes += map->nprobes[i];
		}
	} else {
		probes = map->probes[vmid];
		if (probes == NULL) {
			mutex_exit(&map->mtx);
			return (EINVAL);
		}

		nprobes = map->nprobes[vmid];
	}
	mutex_exit(&map->mtx);

	*count = nprobes;
	return (0);
}
