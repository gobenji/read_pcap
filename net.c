#include <netinet/in.h>
#include <linux/ip.h>

#include "link.h"
#include "net.h"
#include "transport.h"


struct ipv4_priv {
	GHashTable *protocols;
	struct proto *unknown_proto;
};

static void ipv4_parse(struct proto *proto, struct pc_buff *pcb)
{
	struct ipv4_priv *ipv4_priv = proto->priv;
	struct stats *stats = proto->node->data;
	const struct iphdr *hdr = pcb->data;
	unsigned int hdrlen;
	struct proto *next;

	if (pcb->len < sizeof(*hdr)) {
		hdrlen = pcb->len;
		next = ipv4_priv->unknown_proto;
	} else {
		gint protocol;

		hdrlen = hdr->ihl * 4;
		protocol = hdr->protocol;
		next = g_hash_table_lookup(ipv4_priv->protocols, &protocol);
		if (!next) {
			next = ipv4_priv->unknown_proto;
		}
	}

	stats->packets++;
	stats->bytes += hdrlen;

	pcb->network_header = pcb->data;
	pcb_pull(pcb, hdrlen);
	next->ops->parse_packet(next, pcb);
}

static void ipv4_destroy(struct proto* proto)
{
	struct ipv4_priv *ipv4_priv = proto->priv;
	struct stats *stats = proto->node->data;

	ipv4_priv->unknown_proto->ops->destroy(ipv4_priv->unknown_proto);
	g_hash_table_destroy(ipv4_priv->protocols);
	free(ipv4_priv);
	free(stats);
	free(proto);
}

static struct proto_ops ipv4_ops = {
	.parse_packet = &ipv4_parse,
	.destroy = &ipv4_destroy,
};

static struct protocol {
	gint protocol;
	struct proto *(*register_func)(GNode *node);
} known_protocols[] = {
	{IPPROTO_TCP, &register_tcpv4_proto},
	{IPPROTO_UDP, &register_udpv4_proto},
	{0},
};

/* data is a GHashTable value of type struct proto * */
static void destroy_proto(gpointer data)
{
	struct proto *proto = data;

	proto->ops->destroy(proto);
}

struct proto *register_ipv4_proto(GNode *parent)
{
	GHashTable *protocols = g_hash_table_new_full(&g_int_hash, &g_int_equal,
						   NULL, &destroy_proto);
	struct ipv4_priv *ipv4_priv = malloc(sizeof(*ipv4_priv));
	struct stats *stats = calloc(1, sizeof(*stats));
	struct proto *proto = malloc(sizeof(*proto));
	struct protocol *protocol = known_protocols;

	stats->name = "IPv4";
	proto->ops = &ipv4_ops;
	proto->node = g_node_new(stats);

	g_node_append(parent, proto->node);

	while (protocol->protocol) {
		g_hash_table_insert(protocols, &protocol->protocol,
				    protocol->register_func(proto->node));
		protocol++;
	}
	ipv4_priv->protocols = protocols;
	ipv4_priv->unknown_proto = register_unknown_proto(proto->node);
	proto->priv = ipv4_priv;

	return proto;
}
