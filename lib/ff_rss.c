#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <rte_thash.h>
#include <rte_common.h>
#include <netinet/in.h>
#include "ff_net.h"
#include "ff_api.h"
#include "ff_rss.h"
#include "ff_dpdk_if.h"

extern int rsskey_len;
extern uint8_t *rsskey;

static uint32_t ff_softrss(uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport)
{
    uint8_t data[sizeof(saddr) + sizeof(daddr) + sizeof(sport) +
        sizeof(dport)];

    unsigned datalen = 0;

    bcopy(&saddr, &data[datalen], sizeof(saddr));
    datalen += sizeof(saddr);

    bcopy(&daddr, &data[datalen], sizeof(daddr));
    datalen += sizeof(daddr);

    bcopy(&sport, &data[datalen], sizeof(sport));
    datalen += sizeof(sport);

    bcopy(&dport, &data[datalen], sizeof(dport));
    datalen += sizeof(dport);
    return toeplitz_hash(rsskey_len, rsskey, datalen, data);
}

static int pkt_parse_ipv4(void *data, uint16_t len, 
	struct ff_net_hdr_lens *hdr_lens, struct rte_ipv4_hdr **ipv4_hdr)
{
	uint32_t pkt_type = 0;

	memset(hdr_lens, 0, sizeof(*hdr_lens));
	pkt_type = ff_net_get_ptype(data, len, hdr_lens, 
		RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK);

	if (!(pkt_type & RTE_PTYPE_L3_IPV4))
		return -1;
	
	*ipv4_hdr = (struct rte_ipv4_hdr *)(data + hdr_lens->l2_len);
	return 0;
}

static int rss_process(void *data, uint16_t len, uint32_t *rss_value)
{
	struct rte_ipv4_tuple ipv4_tuple;
	struct rte_ipv6_tuple ipv6_tuple;
	struct rte_ipv4_hdr *h_ipv4 = NULL;
	struct ff_net_hdr_lens hdr_lens;
	uint32_t input_len;
	void *tuple;
	uint8_t *src_dst_port;

	if (pkt_parse_ipv4(data, len, &hdr_lens, &h_ipv4))
		return -1;
	
	ipv4_tuple.src_addr = h_ipv4->src_addr;
	ipv4_tuple.dst_addr = h_ipv4->dst_addr;
	ipv4_tuple.sport = 0;
	ipv4_tuple.dport = 0;
	
	if (h_ipv4->next_proto_id == IPPROTO_UDP
		|| h_ipv4->next_proto_id == IPPROTO_TCP)
	{
		src_dst_port = ((void *)h_ipv4) + hdr_lens.l3_len;
		ipv4_tuple.sport = PORT(*(src_dst_port + 1), *src_dst_port);
		ipv4_tuple.dport = PORT(*(src_dst_port + 3), *(src_dst_port + 2));
	} else
		return -1;
	
	*rss_value = ff_softrss(ipv4_tuple.src_addr, ipv4_tuple.dst_addr, 
		ipv4_tuple.sport, ipv4_tuple.dport);
	
	return 0;
}


static int rss_queueid(void *data, uint16_t *len, uint16_t queue_id, uint16_t nb_queues)
{
	int ret;
	uint16_t qid = queue_id;
	uint32_t rss_value = 0;
	
	ret = rss_process(data, *len, &rss_value);

	if (ret == 0 && nb_queues > 0)
		qid = rss_value % nb_queues;
	
	return qid;
}

void ff_rss_init(void)
{
	ff_regist_packet_dispatcher(&rss_queueid);
}

