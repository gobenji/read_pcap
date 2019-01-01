#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>

#include "transport.h"
#include "link.h"
#include "lookup3.h"

#define USEC_PER_SEC	1000000L
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/* from include/net/tcp.h */
static inline bool before(uint32_t seq1, uint32_t seq2)
{
        return (int32_t)(seq1 - seq2) < 0;
}
#define after(seq2, seq1) 	before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline bool between(uint32_t seq1, uint32_t seq2, uint32_t seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

struct segment {
	uint32_t seq, len;
	struct timeval ts_tx, ts_ack, rtt;
	bool acked;
	void *data;
	size_t data_len;
};

struct flow_id {
	struct in_addr dst_addr, src_addr;
	in_port_t dst_port, src_port;
};

struct sk {
	struct flow_id flow_id;

	uint32_t snd_una, snd_nxt;
	/* each element is a struct segment * */
	GQueue sndq;

	struct sk *sibling;
};

static void init_sk(struct sk *sk)
{
	sk->snd_nxt = 0;
	sk->snd_una = 0;
	g_queue_init(&sk->sndq);
}

struct conn_info {
	struct timeval rtt_sum, *max_rtt;
	unsigned int rtt_nb;
	uint64_t data_len;
};

/* Calculate rtt and accumulate info about segment
 *
 * data: a GQueue element of type struct segment *
 * user_data: has type struct conn_info *
 */
static void seg_info_gen(gpointer data, gpointer user_data)
{
	struct segment *seg = data;
	struct conn_info *info = user_data;

	if (seg->acked) {
		timersub(&seg->ts_ack, &seg->ts_tx, &seg->rtt);
		timeradd(&info->rtt_sum, &seg->rtt, &info->rtt_sum);
		info->rtt_nb++;

		if (timercmp(&seg->rtt, info->max_rtt, >)) {
			info->max_rtt = &seg->rtt;
		}
	}
	info->data_len += seg->data_len;
}

/* Tree used to calculate rtt percentiles
 * TYPE: rtt_val
 * FIELD: linkage
 * CMP: compare_rtt
 * NAME: rtt_head
 */
struct rtt_val {
	RB_ENTRY(rtt_val) linkage;
	struct timeval *rtt;
	unsigned int count;
};

static int compare_rtt(struct rtt_val *a, struct rtt_val *b)
{
	if (timercmp(a->rtt, b->rtt, ==)) {
		return 0;
	} else if (timercmp(a->rtt, b->rtt, <)) {
		return -1;
	} else {
		return 1;
	}
}

RB_HEAD(rtt_head, rtt_val);
RB_PROTOTYPE(rtt_head, rtt_val, linkage, compare_rtt);
RB_GENERATE(rtt_head, rtt_val, linkage, compare_rtt);

struct rtt_info {
	struct rtt_head *head;
	unsigned int size;
	unsigned int rrank;
};

/* Accumulate info about rtt for percentile calculation
 *
 * data: a GQueue element of type struct segment *
 * seg->rtt must have been initialized by seg_info_gen already.
 * user_data: has type struct rtt_info *
 */
static void seg_traverse_rtt(gpointer data, gpointer user_data)
{
	struct segment *seg = data;
	struct rtt_info *info = user_data;
	struct rtt_val *new, *current;

	if (!seg->acked) {
		return;
	}

	new = malloc(sizeof(*new));
	new->count = 1;
	new->rtt = &seg->rtt;
	current = RB_INSERT(rtt_head, info->head, new);
	if (current) {
		current->count++;
		free(new);
	}
	info->size++;
	if (info->size > info->rrank) {
		struct rtt_val *val = RB_MIN(rtt_head, info->head);

		if (val->count == 1) {
			RB_REMOVE(rtt_head, info->head, val);
			free(val);
		} else {
			val->count--;
		}
	}
}

/* data: a GQueue element of type struct segment *
 * user_data: offset from byte stream start, type uint32_t *
 */
static void seg_print(gpointer data, gpointer user_data)
{
	uint32_t *offset = user_data;
	struct segment *seg = data;
	char *byte = seg->data;
	char *end;

	if (!seg->data_len) {
		return;
	}

	end = byte + seg->data_len;
	while (byte < end) {
		char *line_start = byte;

		printf("    %08X ", *offset);
		for (; byte < end && byte - line_start < 8; byte++) {
			printf(" %02hhx", *byte);
		}
		printf(" ");
		for (; byte < end && byte - line_start < 16; byte++) {
			printf(" %02hhx", *byte);
		}
		printf("\n");
		*offset += byte - line_start;
	}
}

/* data: a GQueue element of type struct segment *
 * user_data: unused
 */
static void seg_free(gpointer data, gpointer user_data)
{
	struct segment *seg = data;

	free(seg->data);
	free(seg);
}

static void sk_sndq_drain(struct sk *sk, bool do_sibling)
{
	struct conn_info cinfo = {
		.max_rtt = &tv_zero,
	};
	unsigned long rtt_avg = 0;

	g_queue_foreach(&sk->sndq, &seg_info_gen, &cinfo);
	if (cinfo.rtt_nb) {
		rtt_avg = (cinfo.rtt_sum.tv_sec * USEC_PER_SEC +
			   cinfo.rtt_sum.tv_usec) / cinfo.rtt_nb;
	}

	if (cinfo.rtt_nb || cinfo.data_len) {
		struct {
			struct in_addr *addr;
			char addr_buf[INET_ADDRSTRLEN];
		} addrs[] = {
			{
				.addr = &sk->flow_id.src_addr,
			},
			{
				.addr = &sk->flow_id.dst_addr,
			},
		};
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(addrs); i++) {
			if (inet_ntop(AF_INET, addrs[i].addr,
				      addrs[i].addr_buf,
				      sizeof(addrs[i].addr_buf)) == NULL) {
				pr_perror("inet_ntop");
			}
		}

		printf("Connection %s:%u > %s:%u:\n",
		       addrs[0].addr_buf, ntohs(sk->flow_id.src_port),
		       addrs[1].addr_buf, ntohs(sk->flow_id.dst_port));
	}
	if (cinfo.rtt_nb) {
		ldiv_t rtt_usec = ldiv(rtt_avg, USEC_PER_SEC);
		struct rtt_head head = RB_INITIALIZER(&head);
		struct rtt_info rinfo = {
			.head = &head,
			.rrank = cinfo.rtt_nb -
				DIV_ROUND_UP(95 * cinfo.rtt_nb, 100) + 1,
		};
		struct rtt_val *val, *nxt;
		
		/* traverse all segments while saving the largest rrank number
		 * of rtt values
		 */
		g_queue_foreach(&sk->sndq, &seg_traverse_rtt, &rinfo);
		val = RB_MIN(rtt_head, &head);

		printf("    avgrtt %lu.%06lu 95th percentile %lu.%06lu max %lu.%06lu (%u sample%s)\n",
		       rtt_usec.quot, rtt_usec.rem,
		       val->rtt->tv_sec, val->rtt->tv_usec,
		       cinfo.max_rtt->tv_sec, cinfo.max_rtt->tv_usec,
		       cinfo.rtt_nb, cinfo.rtt_nb > 1 ? "s" : "");

		for (; val != NULL; val = nxt) {
			nxt = RB_NEXT(rtt_head, &head, val);
			RB_REMOVE(rtt_head, &head, val);
			free(val);
		}
	}
	if (cinfo.data_len) {
		uint32_t offset = 0;

		printf("    captured payload data, len %lu\n", cinfo.data_len);
		g_queue_foreach(&sk->sndq, &seg_print, &offset);
	}

	g_queue_foreach(&sk->sndq, &seg_free, NULL);
	g_queue_clear(&sk->sndq);

	/* For a nicer output, drain the sibling right after */
	if (do_sibling && sk->sibling &&
	    !g_queue_is_empty(&sk->sibling->sndq)) {
		sk_sndq_drain(sk->sibling, false);
	}
}

/* data: GHashTable value of type struct sk * */
static void destroy_sk(gpointer data)
{
	struct sk *sk = data;

	if (verbose) {
		char addr_buf[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, &sk->flow_id.src_addr, addr_buf,
			      sizeof(addr_buf)) == NULL) {
			pr_perror("inet_ntop");
		}

		if (inet_ntop(AF_INET, &sk->flow_id.dst_addr, addr_buf,
			      sizeof(addr_buf)) == NULL) {
			pr_perror("inet_ntop");
		}
	}

	sk_sndq_drain(sk, true);
	if (sk->sibling) {
		sk->sibling->sibling = NULL;
	}
	free(sk);
}

/* Mark segments with seq# in the [from, to[ interval as acked at time tstamp
 *
 * q: GQueue whose elements are struct segment *
 */
static void sk_q_record_ack(GQueue *q, uint32_t from, uint32_t to,
			    const struct timeval *tstamp)
{
	GList *e;
	bool found = false;
	uint32_t nxt;

	e = g_queue_peek_tail_link(q);
	if (e) {
		struct segment *seg = e->data;

		nxt = seg->seq + seg->len;
	}
	while (e) {
		struct segment *seg = e->data;
		/* first seq# beyond the end of the segment */
		uint32_t end_seq = seg->seq + seg->len;

		/* do not wrap around */
		if (nxt != end_seq && !before(end_seq, nxt)) {
			break;
		}

		if (between(seg->seq, from, to) && between(end_seq, from, to)) {
			seg->acked = true;
			memcpy(&seg->ts_ack, tstamp, sizeof(seg->ts_ack));
			found = true;
		} else if (found) {
			/* we've gone beyond the [from, to[ interval */
			break;
		}
		e = e->prev;
	}
}

/* data is a GHashTable key of type struct flow_id * */
static guint flow_id_hash(gconstpointer key)
{
	const struct flow_id *fl = key;
	uint32_t a, b, c;

	a = fl->dst_addr.s_addr;
	b = fl->src_addr.s_addr;
	c = fl->src_port << 16 | fl->dst_port;
	final(a, b, c);

	return c;
}

/* a, b are GHashTable keys of type struct flow_id * */
static gboolean flow_id_equal(gconstpointer a, gconstpointer b)
{
	const struct flow_id *fla = a, *flb = b;
	if (fla->dst_addr.s_addr == flb->dst_addr.s_addr &&
	    fla->src_addr.s_addr == flb->src_addr.s_addr &&
	    fla->dst_port == flb->dst_port &&
	    fla->src_port == flb->src_port) {
		return TRUE;
	} else {
		return FALSE;
	}
}

struct tcpv4_priv {
	GHashTable *sockets;
	struct proto *payload_proto;
};

static void tcp_update(struct tcpv4_priv *priv, struct pc_buff *pcb)
{
	const struct iphdr *iph = pcb->network_header;
	const struct tcphdr *tcph = pcb->transport_header;
	struct flow_id fl = {
		.dst_addr.s_addr = iph->daddr,
		.src_addr.s_addr = iph->saddr,
		.dst_port = tcph->dest,
		.src_port = tcph->source,
	};
	struct sk *dst_sk, *src_sk;
	uint32_t seq, next_seq, data_len;

	if (verbose) {
		char addr_buf[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, &fl.src_addr, addr_buf,
			      sizeof(addr_buf)) == NULL) {
			pr_perror("inet_ntop");
		}
		printf("%s:%u > ", addr_buf, ntohs(fl.src_port));

		if (inet_ntop(AF_INET, &fl.dst_addr, addr_buf,
			      sizeof(addr_buf)) == NULL) {
			pr_perror("inet_ntop");
		}
		printf("%s:%u: ", addr_buf, ntohs(fl.dst_port));
		printf("Flags [%s%s%s]",
		       tcph->syn ? "S" : "",
		       tcph->ack ? "." : "",
		       tcph->psh ? "P" : "");
	}

	src_sk = g_hash_table_lookup(priv->sockets, &fl);
	if (!src_sk) {
		src_sk = malloc(sizeof(*src_sk));
		dst_sk = malloc(sizeof(*dst_sk));

		init_sk(src_sk);
		src_sk->flow_id = fl;
		src_sk->sibling = dst_sk;

		init_sk(dst_sk);
		dst_sk->flow_id.dst_addr.s_addr = fl.src_addr.s_addr;
		dst_sk->flow_id.src_addr.s_addr = fl.dst_addr.s_addr;
		dst_sk->flow_id.dst_port = fl.src_port;
		dst_sk->flow_id.src_port = fl.dst_port;
		dst_sk->sibling = src_sk;

		g_hash_table_insert(priv->sockets, &src_sk->flow_id, src_sk);
		g_hash_table_insert(priv->sockets, &dst_sk->flow_id, dst_sk);
	} else {
		dst_sk = src_sk->sibling;
	}

	seq = ntohl(tcph->seq);
	if (tcph->syn) {
		src_sk->snd_una = src_sk->snd_nxt = seq;
		sk_sndq_drain(src_sk, false);
	}

	data_len = ntohs(iph->tot_len) - (pcb->data - pcb->network_header);
	next_seq = seq + data_len + tcph->syn + tcph->fin;
	if (after(next_seq, src_sk->snd_nxt)) {
		struct segment *seg = malloc(sizeof(*seg));

		src_sk->snd_nxt = next_seq;

		seg->seq = seq;
		seg->len = next_seq - seq;
		memcpy(&seg->ts_tx, pcb->tstamp, sizeof(seg->ts_tx));
		seg->acked = false;
		if (pcb->len) {
			data_len = MIN(data_len, pcb->len);
			seg->data = malloc(data_len);
			seg->data_len = data_len;
			memcpy(seg->data, pcb->data, data_len);
		} else {
			seg->data = NULL;
			seg->data_len = 0;
		}
		g_queue_push_tail(&src_sk->sndq, seg);
	}

	if (tcph->ack) {
		uint32_t ack_seq = ntohl(tcph->ack_seq);

		if (after(ack_seq, dst_sk->snd_una)) {
			sk_q_record_ack(&dst_sk->sndq, dst_sk->snd_una,
					ack_seq, pcb->tstamp);
			dst_sk->snd_una = ack_seq;
		}
	}
}

static void tcpv4_parse(struct proto *proto, struct pc_buff *pcb)
{
	struct tcpv4_priv *tcpv4_priv = proto->priv;
	struct stats *stats = proto->node->data;
	const struct tcphdr *hdr = pcb->data;
	unsigned int hdrlen;
	bool do_update = true;

	if (pcb->len < sizeof(*hdr)) {
		hdrlen = pcb->len;
		do_update = false;
	} else {
		hdrlen = hdr->doff * 4;
	}

	stats->packets++;
	stats->bytes += hdrlen;

	pcb->transport_header = pcb->data;

	pcb_pull(pcb, hdrlen);
	if (do_update) {
		tcp_update(tcpv4_priv, pcb);
		tcpv4_priv->payload_proto->ops->parse_packet(
			tcpv4_priv->payload_proto, pcb);
	}
}

static void tcpv4_destroy(struct proto* proto)
{
	struct tcpv4_priv *tcpv4_priv = proto->priv;
	struct stats *stats = proto->node->data;

	tcpv4_priv->payload_proto->ops->destroy(tcpv4_priv->payload_proto);
	if (g_hash_table_size(tcpv4_priv->sockets)) {
		/* in expectation that a list of Connection info will follow */
		printf("\n");
	}
	g_hash_table_destroy(tcpv4_priv->sockets);
	free(tcpv4_priv);
	free(stats);
	free(proto);
}

static struct proto_ops tcpv4_ops = {
	.parse_packet = &tcpv4_parse,
	.destroy = &tcpv4_destroy,
};

struct proto *register_tcpv4_proto(GNode *parent)
{
	struct tcpv4_priv *tcpv4_priv = malloc(sizeof(*tcpv4_priv));
	struct stats *stats = calloc(1, sizeof(*stats));
	struct proto *proto = malloc(sizeof(*proto));

	stats->name = "TCP";
	proto->ops = &tcpv4_ops;
	proto->node = g_node_new(stats);

	g_node_append(parent, proto->node);

	tcpv4_priv->sockets = g_hash_table_new_full(
		&flow_id_hash, &flow_id_equal, NULL, &destroy_sk);
	tcpv4_priv->payload_proto = register_unknown_proto(proto->node);
	((struct stats *)(tcpv4_priv->payload_proto->node->data))->name =
		"payload";
	proto->priv = tcpv4_priv;

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
