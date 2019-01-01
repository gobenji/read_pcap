#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "link.h"
#include "net.h"


struct ether_priv {
	GHashTable *ptypes;
	struct proto *unknown_proto;
};

static void ether_parse(struct proto *proto, struct pc_buff *pcb)
{
	struct ether_priv *ether_priv = proto->priv;
	struct stats *stats = proto->node->data;
	const struct ethhdr *hdr = pcb->data;
	unsigned int hdrlen;
	struct proto *next;

	if (pcb->len < ETH_HLEN) {
		hdrlen = pcb->len;
		next = ether_priv->unknown_proto;
	} else {
		gint eth_type;

		hdrlen = ETH_HLEN;
		eth_type = ntohs(hdr->h_proto);
		next = g_hash_table_lookup(ether_priv->ptypes, &eth_type);
		if (!next) {
			next = ether_priv->unknown_proto;
		}
	}

	stats->packets++;
	stats->bytes += hdrlen;

	pcb_pull(pcb, hdrlen);
	next->ops->parse_packet(next, pcb);
}

static void ether_destroy(struct proto* proto)
{
	struct ether_priv *ether_priv = proto->priv;
	struct stats *stats = proto->node->data;

	ether_priv->unknown_proto->ops->destroy(ether_priv->unknown_proto);
	g_hash_table_destroy(ether_priv->ptypes);
	free(ether_priv);
	free(stats);
	free(proto);
}

static struct proto_ops ether_ops = {
	.parse_packet = &ether_parse,
	.destroy = &ether_destroy,
};

static struct ptype {
	gint eth_type;
	struct proto *(*register_func)(GNode *node);
} known_types[] = {
	{ETH_P_IP, &register_ipv4_proto},
	{0},
};

/* data is a GHashTable value of type struct proto * */
static void destroy_proto(gpointer data)
{
	struct proto *proto = data;

	proto->ops->destroy(proto);
}

struct proto *register_ether_proto(GNode *parent)
{
	GHashTable *ptypes = g_hash_table_new_full(&g_int_hash, &g_int_equal,
						   NULL, &destroy_proto);
	struct ether_priv *ether_priv = malloc(sizeof(*ether_priv));
	struct stats *stats = calloc(1, sizeof(*stats));
	struct proto *proto = malloc(sizeof(*proto));
	struct ptype *ptype = known_types;

	stats->name = "Ethernet";
	proto->ops = &ether_ops;
	proto->node = g_node_new(stats);

	g_node_append(parent, proto->node);

	while (ptype->eth_type) {
		g_hash_table_insert(ptypes, &ptype->eth_type,
				    ptype->register_func(proto->node));
		ptype++;
	}
	ether_priv->ptypes = ptypes;
	ether_priv->unknown_proto = register_unknown_proto(proto->node);
	proto->priv = ether_priv;;

	return proto;
}

static void unknown_parse(struct proto *proto, struct pc_buff *pcb)
{
	struct stats *stats = proto->node->data;

	stats->packets++;
	stats->bytes += pcb->len;
}

static void unknown_destroy(struct proto* proto)
{
	struct stats *stats = proto->node->data;

	free(stats);
	free(proto);
}

static struct proto_ops unknown_ops = {
	.parse_packet = &unknown_parse,
	.destroy = &unknown_destroy,
};

struct proto *register_unknown_proto(GNode *parent)
{
	struct proto *proto = malloc(sizeof(*proto));
	struct stats *stats = calloc(1, sizeof(*stats));

	stats->name = "unknown";
	proto->ops = &unknown_ops;
	proto->node = g_node_new(stats);

	g_node_append(parent, proto->node);

	return proto;
}
