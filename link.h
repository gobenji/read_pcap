#ifndef _LINK_H
#define _LINK_H

#include <gmodule.h>

#include "read_pcap.h"


struct proto *register_ether_proto(GNode *parent);
struct proto *register_unknown_proto(GNode *parent);

#endif /* _LINK_H */
