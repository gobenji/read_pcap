#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include "read_pcap.h"
#include "link.h"


bool verbose = false;

struct context {
	GNode *node;
	struct stats stats;

	struct proto *ether_proto;
};

static void parse_packet(u_char *_context, const struct pcap_pkthdr *h,
			 const u_char *bytes)
{
	struct context *context = (struct context *)_context;
	struct pc_buff pcb = {
		.head = bytes,
		.data = bytes,
		.len = h->caplen,
		.tstamp = &h->ts,
	};

	context->stats.packets++;
	context->stats.bytes += h->len;

	if (verbose) {
		printf("frame %-6lu ", context->stats.packets);
	}

	context->ether_proto->ops->parse_packet(context->ether_proto, &pcb);

	if (verbose) {
		printf(", length %u/%u\n", h->caplen, h->len);
	}
}

/* result must be preallocated to a buffer of size >= 5 */
static void format_percent(long num, long denom, char *result)
{
	ldiv_t retval;

	if (denom == 0) {
		strcpy(result, "NA");
		return;
	}
	if (num > denom) {
		strcpy(result, ">100");
		return;
	}

	retval = ldiv(num * 100, denom);
	if (retval.quot < 0) {
		strcpy(result, "<0");
	} else if (retval.quot == 0 && retval.rem > 0) {
		strcpy(result, "<1");
	} else {
		snprintf(result, 5, "%ld", retval.quot);
	}
}

/*
 * node: struct stats *, stats for this node
 * data: struct stats *, top level stats
 */
static gboolean print_stats(GNode *node, gpointer data)
{
	struct stats *stats = (struct stats *)node->data;
	struct stats *global = (struct stats *)data;
	unsigned int level = g_node_depth(node) - 1;
	const unsigned int indent = 3;
	char packets_p[5], bytes_p[5];

	format_percent(stats->packets, global->packets, packets_p);
	format_percent(stats->bytes, global->bytes, bytes_p);

	/* level is in [0..4]: total, link, net, transport, application */
	assert(level <= 4);
	printf("%*s%-19s%*s  %10" PRIu64 "  (%3s%%)  %12" PRIu64 "  (%3s%%)\n",
	       level * indent, "", stats->name, (4 - level) * indent, "",
	       stats->packets, packets_p, stats->bytes, bytes_p);

	return FALSE;
}

static void print_hierarchy(struct context *context)
{
	g_node_traverse(context->node, G_PRE_ORDER, G_TRAVERSE_ALL, -1,
			&print_stats, &context->stats);
}

void print_usage(FILE *stream, char *name)
{
	fprintf(stream, "Usage: %s [options] <capture file>\n", name);
	fprintf(stream, "\n");
	fprintf(stream, "options:\n");
	fprintf(stream, "-v, --verbose  Print debugging messages.\n");
	fprintf(stream, "-h, --help     Show this help message and exit.\n");
}

struct timeval tv_zero;

int main(int argc, char **argv)
{
	struct context context = {
		.stats = {
			.name = "Total (on the wire)",
		},
	};
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *fname;
	int err = 0;
	int retval;
	pcap_t *p;

	/* parse args */
	while (true) {
		static struct option long_options[] = {
			{"verbose", no_argument, NULL, 'v'},
			{"help", no_argument, NULL, 'h'},
			{NULL, 0, NULL, 0}
		};
		int c;

		c = getopt_long(argc, argv, "vh", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'v':
			verbose = true;
			break;

		case 'h':
			print_usage(stdout, argv[0]);
			return 0;

		case '?':
			fprintf(stderr, "getopt_long error\n");
			print_usage(stderr, argv[0]);
			return 1;
		}
	}

	fname = argv[optind++];

	if (optind != argc) {
		fprintf(stderr, "wrong number of arguments\n");
		print_usage(stderr, argv[0]);
		return 1;
	}

	timerclear(&tv_zero);

	/* read capture file */
	if ((p = pcap_open_offline(fname, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open: %s\n", errbuf);
		return 1;
	}

	retval = pcap_datalink(p);
	if (verbose) {
		printf("%s linktype: %d\n", fname, retval);
	}
	if (retval != DLT_EN10MB) {
		fprintf(stderr, "Unhandled link type %d\n", retval);
		err = 1;
		goto out_close;
	}

	context.node = g_node_new(&context.stats);
	/* Register an instance of the proto parser specific to this
	 * context/pcap file
	 */
	context.ether_proto = register_ether_proto(context.node);

	if (pcap_loop(p, -1, &parse_packet, (u_char *)&context) == -1) {
		pcap_perror(p, "pcap_loop: ");
		err = 1;
		goto out_destroy;
	}

	if (verbose && context.stats.packets) {
		/* for a nicer output, separate from the list of frames */
		printf("\n");
	}
	printf("Protocol hierarchy\n");
	printf("%-32s  %8s           %8s         \n", "protocol", "packets",
	       "bytes");
	print_hierarchy(&context);

out_destroy:
	context.ether_proto->ops->destroy(context.ether_proto);
	g_node_destroy(context.node);

out_close:
	pcap_close(p);

	return err;
}
