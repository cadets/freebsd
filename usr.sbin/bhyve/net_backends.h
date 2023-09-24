/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Vincenzo Maffione <vmaffione@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __NET_BACKENDS_H__
#define __NET_BACKENDS_H__

#include <stdint.h>

/* Opaque type representing a network backend. */
typedef struct net_backend net_backend_t;

/* Interface between network frontends and the network backends. */
typedef void (*net_be_rxeof_t)(int, enum ev_type, void *param);
int	netbe_init(net_backend_t **be, nvlist_t *nvl, net_be_rxeof_t cb,
            void *param);
int	netbe_legacy_config(nvlist_t *nvl, const char *opts);
void	netbe_cleanup(net_backend_t *be);
uint64_t netbe_get_cap(net_backend_t *be);
int	 netbe_set_cap(net_backend_t *be, uint64_t cap,
             unsigned vnet_hdr_len);
size_t	netbe_get_vnet_hdr_len(net_backend_t *be);
ssize_t	netbe_send(net_backend_t *be, const struct iovec *iov, int iovcnt);
ssize_t	netbe_peek_recvlen(net_backend_t *be);
ssize_t	netbe_recv(net_backend_t *be, const struct iovec *iov, int iovcnt);
ssize_t	netbe_rx_discard(net_backend_t *be);
void	netbe_rx_disable(net_backend_t *be);
void	netbe_rx_enable(net_backend_t *be);
int	netbe_tagging_enabled(net_backend_t *be);
int	netbe_tagging_supported(net_backend_t *be);
int	netbe_tagging_enable(net_backend_t *be);


/*
 * Network device capabilities taken from the VirtIO standard.
 * Despite the name, these capabilities can be used by different frontents
 * (virtio-net, ptnet) and supported by different backends (netmap, tap, ...).
 */
#define	VIRTIO_NET_F_CSUM	(1ULL <<  0) /* host handles partial cksum */
#define	VIRTIO_NET_F_GUEST_CSUM	(1ULL <<  1) /* guest handles partial cksum */
#define	VIRTIO_NET_F_MTU	(1ULL <<  3) /* initial MTU advice */
#define	VIRTIO_NET_F_MAC	(1ULL <<  5) /* host supplies MAC */
#define	VIRTIO_NET_F_GSO_DEPREC	(1ULL <<  6) /* deprecated: host handles GSO */
#define	VIRTIO_NET_F_GUEST_TSO4	(1ULL <<  7) /* guest can rcv TSOv4 */
#define	VIRTIO_NET_F_GUEST_TSO6	(1ULL <<  8) /* guest can rcv TSOv6 */
#define	VIRTIO_NET_F_GUEST_ECN	(1ULL <<  9) /* guest can rcv TSO with ECN */
#define	VIRTIO_NET_F_GUEST_UFO	(1ULL << 10) /* guest can rcv UFO */
#define	VIRTIO_NET_F_HOST_TSO4	(1ULL << 11) /* host can rcv TSOv4 */
#define	VIRTIO_NET_F_HOST_TSO6	(1ULL << 12) /* host can rcv TSOv6 */
#define	VIRTIO_NET_F_HOST_ECN	(1ULL << 13) /* host can rcv TSO with ECN */
#define	VIRTIO_NET_F_HOST_UFO	(1ULL << 14) /* host can rcv UFO */
#define	VIRTIO_NET_F_MRG_RXBUF	(1ULL << 15) /* host can merge RX buffers */
#define	VIRTIO_NET_F_STATUS	(1ULL << 16) /* config status field available */
#define	VIRTIO_NET_F_CTRL_VQ	(1ULL << 17) /* control channel available */
#define	VIRTIO_NET_F_CTRL_RX	(1ULL << 18) /* control channel RX mode support */
#define	VIRTIO_NET_F_CTRL_VLAN	(1ULL << 19) /* control channel VLAN filtering */
#define	VIRTIO_NET_F_GUEST_ANNOUNCE \
				(1ULL << 21) /* guest can send gratuitous pkts */
#define	VIRTIO_NET_F_MQ		(1ULL << 22) /* host supports multiple VQ pairs */
#define VIRTIO_NET_F_TAGGING	(1ULL << 57) /* host supports tagging packets */

/*
 * Fixed network header size
 */
struct virtio_net_rxhdr {
	uint8_t		vrh_flags;
	uint8_t		vrh_gso_type;
	uint16_t	vrh_hdr_len;
	uint16_t	vrh_gso_size;
	uint16_t	vrh_csum_start;
	uint16_t	vrh_csum_offset;
	uint16_t	vrh_bufs;
} __packed;

#endif /* __NET_BACKENDS_H__ */
