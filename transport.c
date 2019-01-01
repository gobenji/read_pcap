#include <linux/tcp.h>
#include <linux/udp.h>

#include "transport.h"


static void tcpv4_parse(struct proto *proto, struct pc_buff *pcb)
{
	struct stats *stats = proto->node->data;
	const struct tcphdr *hdr = pcb->data;
	unsigned int hdrlen;

	if (pcb->len < sizeof(*hdr)) {
		hdrlen = pcb->len;
	} else {
		hdrlen = hdr->doff * 4;
	}

	stats->packets++;
	stats->bytes += hdrlen;

	pcb->transport_header = pcb->data;
	pcb_pull(pcb, hdrlen);
}

static void tcpv4_destroy(struct proto* proto)
{
	struct stats *stats = proto->node->data;

	free(stats);
	free(proto);
}

static struct proto_ops tcpv4_ops = {
	.parse_packet = &tcpv4_parse,
	.destroy = &tcpv4_destroy,
};

struct proto *register_tcpv4_proto(GNode *parent)
{
	struct proto *proto = malloc(sizeof(*proto));
	struct stats *stats = calloc(1, sizeof(*stats));

	stats->name = "TCP";
	proto->ops = &tcpv4_ops;
	proto->node = g_node_new(stats);

	g_node_append(parent, proto->node);

	return proto;
}

static void udpv4_parse(struct proto *proto, struct pc_buff *pcb)
{
	struct stats *stats = proto->node->data;
	const struct udphdr *hdr = pcb->data;
	unsigned int hdrlen;

	if (pcb->len < sizeof(*hdr)) {
		hdrlen = pcb->len;
	} else {
		hdrlen = sizeof(*hdr);
	}

	stats->packets++;
	stats->bytes += hdrlen;

	pcb->transport_header = pcb->data;
	pcb_pull(pcb, hdrlen);
}

static void udpv4_destroy(struct proto* proto)
{
	struct stats *stats = proto->node->data;

	free(stats);
	free(proto);
}

static struct proto_ops udpv4_ops = {
	.parse_packet = &udpv4_parse,
	.destroy = &udpv4_destroy,
};

struct proto *register_udpv4_proto(GNode *parent)
{
	struct proto *proto = malloc(sizeof(*proto));
	struct stats *stats = calloc(1, sizeof(*stats));

	stats->name = "UDP";
	proto->ops = &udpv4_ops;
	proto->node = g_node_new(stats);

	g_node_append(parent, proto->node);

	return proto;
}
