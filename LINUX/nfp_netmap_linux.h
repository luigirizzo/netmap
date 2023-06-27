/*
 * Copyright (C) 2023, Giuseppe Lettieri. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <bsd_glue.h>
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>

#ifdef NETMAP_NFP_NET
/* prevent name clash */
#undef cdev
#endif /* NETMAP_NFP_NET */

#ifdef NETMAP_NFP_DP

static int
nfp_netmap_configure_rx_ring(struct nfp_net *nn, struct nfp_net_rx_ring *rx_ring)
{
	(void)nn;
	nm_prinf("idx %d", rx_ring->idx);
	return 0;
}

static int
nfp_netmap_configure_tx_ring(struct nfp_net *nn, struct nfp_net_tx_ring *tx_ring)
{
	(void)nn;
	nm_prinf("idx %d", tx_ring->idx);
	return 0;
}

#endif /* NETMAP_NFP_DP */

#ifdef NETMAP_NFP_MAIN

static int
nfp_netmap_reg(struct netmap_adapter *na, int onoff)
{
	struct ifnet *ifp = na->ifp;
	struct nfp_net *nn = netdev_priv(ifp);
	struct nfp_net_dp *dp;

	dp = nfp_net_clone_dp(nn);
	if (!dp)
		return 1;

	if (onoff) {
		nm_set_native_flags(na);
	} else {
		nm_clear_native_flags(na);
	}

	return nfp_net_ring_reconfig(nn, dp, NULL);
}

static int
nfp_netmap_txsync(struct netmap_kring *kring, int flags)
{
	(void)kring;
	(void)flags;
	return 0;
}

static int
nfp_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	(void)kring;
	(void)flags;
	return 0;
}

static int
nfp_netmap_config(struct netmap_adapter *na, struct nm_config_info *info)
{
	int ret = netmap_rings_config_get(na, info);

	if (ret) {
		return ret;
	}

	info->rx_buf_maxsize = NETMAP_BUF_SIZE(na);

	return 0;
}

static int
nfp_netmap_bufcfg(struct netmap_kring *kring, uint64_t target)
{
	(void)kring;
	(void)target;
	nm_prinf("called target %llx", target);
	return 0;
}

static void
nfp_netmap_attach(struct nfp_net *nn)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = nn->dp.netdev;
	na.pdev = &nn->pdev->dev;
	na.na_flags = NAF_MOREFRAG | NAF_OFFSETS;
	na.num_tx_desc = nn->dp.txd_cnt;
	na.num_rx_desc = nn->dp.rxd_cnt;
	na.num_tx_rings = nn->dp.num_tx_rings;
	na.num_rx_rings = nn->dp.num_rx_rings;
	na.rx_buf_maxsize = 4096;
	na.nm_txsync = nfp_netmap_txsync;
	na.nm_rxsync = nfp_netmap_rxsync;
	na.nm_register = nfp_netmap_reg;
	na.nm_config = nfp_netmap_config;
	na.nm_bufcfg = nfp_netmap_bufcfg;
	netmap_attach(&na);
}
#endif /* NETMAP_NFP_MAIN */
