/* iptables target module for using NMRING mechanism
 *
 * Copyright 2018, Allied Telesis Labs New Zealand, Ltd
 *
*/
#ifndef _XT_NMRING_TARGET_H
#define _XT_NMRING_TARGET_H

#include <linux/types.h>

/* target info */
struct xt_nmring_info {
	char ifc_pipe[IFNAMSIZ + 1];
	void *priv __attribute__((aligned(8)));
};

#endif /* _XT_NMRING_TARGET_H */
