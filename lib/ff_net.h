/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 */

#ifndef _FSTACK_NET_H_
#define _FSTACK_NET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>

/**
 * Structure containing header lengths associated to a packet, filled
 * by rte_net_get_ptype().
 */
struct ff_net_hdr_lens {
	uint8_t l2_len;
	uint8_t inner_l2_len;
	uint16_t l3_len;
	uint16_t inner_l3_len;
	uint16_t tunnel_len;
	uint8_t l4_len;
	uint8_t inner_l4_len;
};

/**
 * Skip IPv6 header extensions.
 *
 * This function skips all IPv6 extensions, returning size of
 * complete header including options and final protocol value.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * @param proto
 *   Protocol field of IPv6 header.
 * @param m
 *   The packet mbuf to be parsed.
 * @param off
 *   On input, must contain the offset to the first byte following
 *   IPv6 header, on output, contains offset to the first byte
 *   of next layer (after any IPv6 extension header)
 * @param frag
 *   Contains 1 in output if packet is an IPv6 fragment.
 * @return
 *   Protocol that follows IPv6 header.
 *   -1 if an error occurs during mbuf parsing.
 */
__rte_experimental
int
ff_net_skip_ip6_ext(uint16_t proto, const void *data, uint16_t data_len, uint32_t *off,
	int *frag);

/**
 * Parse an Ethernet packet to get its packet type.
 *
 * This function parses the network headers in mbuf data and return its
 * packet type.
 *
 * If it is provided by the user, it also fills a rte_net_hdr_lens
 * structure that contains the lengths of the parsed network
 * headers. Each length field is valid only if the associated packet
 * type is set. For instance, hdr_lens->l2_len is valid only if
 * (retval & RTE_PTYPE_L2_MASK) != RTE_PTYPE_UNKNOWN.
 *
 * Supported packet types are:
 *   L2: Ether, Vlan, QinQ
 *   L3: IPv4, IPv6
 *   L4: TCP, UDP, SCTP
 *   Tunnels: IPv4, IPv6, Gre, Nvgre
 *
 * @param m
 *   The packet mbuf to be parsed.
 * @param hdr_lens
 *   A pointer to a structure where the header lengths will be returned,
 *   or NULL.
 * @param layers
 *   List of layers to parse. The function will stop at the first
 *   empty layer. Examples:
 *   - To parse all known layers, use RTE_PTYPE_ALL_MASK.
 *   - To parse only L2 and L3, use RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK
 * @return
 *   The packet type of the packet.
 */
uint32_t ff_net_get_ptype(const void *data, uint16_t data_len,
	struct ff_net_hdr_lens *hdr_lens, uint32_t layers);


#ifdef __cplusplus
}
#endif


#endif /*ifndef _FSTACK_NET_H_ */

