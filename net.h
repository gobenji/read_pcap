#ifndef _NET_H
#define _NET_H

#include <gmodule.h>

#include "read_pcap.h"


struct proto *register_ipv4_proto(GNode *parent);

#endif /* _NET_H */
