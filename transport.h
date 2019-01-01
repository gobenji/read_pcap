#ifndef _TRANSPORT_H
#define _TRANSPORT_H

#include <gmodule.h>

#include "read_pcap.h"


struct proto *register_tcpv4_proto(GNode *parent);
struct proto *register_udpv4_proto(GNode *parent);

#endif /* _TRANSPORT_H */
