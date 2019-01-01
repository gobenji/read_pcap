#ifndef _READ_PCAP_H
#define _READ_PCAP_H

#include <assert.h>
#include <gmodule.h>
#include <pcap/pcap.h>
#include <stdbool.h>


extern bool verbose;

/* sk_buff's little cousin ;) */
struct pc_buff {
	const void *head, *data;
	size_t len;

	const void *network_header, *transport_header;
};

static inline const void *pcb_pull(struct pc_buff *pcb, unsigned int len)
{
	assert(len <= pcb->len);
	pcb->len -= len;
	pcb->data += len;
	return pcb->data;
}

/* layer-agnostic proto */
struct proto;

struct proto_ops {
	void (*parse_packet)(struct proto *proto, struct pc_buff *pcb);
	void (*destroy)(struct proto *proto);
};

struct stats {
	char *name;
	uint64_t packets;
	uint64_t bytes;
};

struct proto {
	struct proto_ops *ops;

	/* node->data is a struct stats * */
	GNode *node;

	/* proto-specific private data */
	void *priv;
};

#endif /* _READ_PCAP_H */
