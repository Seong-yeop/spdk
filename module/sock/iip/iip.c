/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (c) 2026.
 */

#include "spdk/stdinc.h"

#include <arpa/inet.h>
#include <pthread.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_thash.h>

#include "spdk/env.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk_internal/sock.h"

#ifndef RTE_MBUF_F_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD PKT_RX_IP_CKSUM_GOOD
#endif
#ifndef RTE_MBUF_F_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD PKT_RX_L4_CKSUM_GOOD
#endif
#ifndef RTE_MBUF_F_TX_IP_CKSUM
#define RTE_MBUF_F_TX_IP_CKSUM PKT_TX_IP_CKSUM
#endif
#ifndef RTE_MBUF_F_TX_IPV4
#define RTE_MBUF_F_TX_IPV4 PKT_TX_IPV4
#endif
#ifndef RTE_MBUF_F_TX_TCP_CKSUM
#define RTE_MBUF_F_TX_TCP_CKSUM PKT_TX_TCP_CKSUM
#endif
#ifndef RTE_MBUF_F_TX_UDP_CKSUM
#define RTE_MBUF_F_TX_UDP_CKSUM PKT_TX_UDP_CKSUM
#endif
#ifndef RTE_MBUF_F_TX_TCP_SEG
#define RTE_MBUF_F_TX_TCP_SEG PKT_TX_TCP_SEG
#endif
#ifndef RTE_MBUF_F_TX_UDP_SEG
#define RTE_MBUF_F_TX_UDP_SEG 0
#endif
#ifndef RTE_ETH_TX_OFFLOAD_UDP_TSO
#define RTE_ETH_TX_OFFLOAD_UDP_TSO 0
#endif

#define IIP_SOCK_RX_DESC		1024
#define IIP_SOCK_TX_DESC		1024
#define IIP_SOCK_RX_BATCH		32
#define IIP_SOCK_TX_BATCH		32
#define IIP_SOCK_MBUF_CACHE_SIZE	256
#define IIP_SOCK_MBUF_DATA_ROOM		0xffff
#define IIP_SOCK_CLONE_MBUF_DATA_ROOM	RTE_MBUF_DEFAULT_BUF_SIZE
#define IIP_SOCK_MAX_SEND_CHUNK		(60 * 1024)
#define IIP_SOCK_NETSTACK_PB		8192
#define IIP_SOCK_NETSTACK_TCP_CONN	4096

#define __iip_memcpy	memcpy
#define __iip_memset	memset
#define __iip_memcmp	memcmp
#define __iip_memmove	memmove
#define __iip_assert	assert

#ifdef IIP_SOCK_ENABLE_DEBUG_LOG
#define IIP_OPS_DEBUG_PRINTF(...) SPDK_DEBUGLOG(sock_iip, __VA_ARGS__)
#else
#define IIP_OPS_DEBUG_PRINTF(...) do { if (0) { SPDK_DEBUGLOG(sock_iip, __VA_ARGS__); } } while (0)
#endif

#ifdef IIP_SOCK_ENABLE_TRACE_LOG
#define IIP_SOCK_TRACELOG(...) SPDK_NOTICELOG(__VA_ARGS__)
#else
#define IIP_SOCK_TRACELOG(...) do { if (0) { SPDK_NOTICELOG(__VA_ARGS__); } } while (0)
#endif

static void iip_ops_util_now_ns(uint32_t t[3], void *opaque);

#include "iip/main.c"

TAILQ_HEAD(iip_sock_tailq, spdk_iip_sock);
TAILQ_HEAD(iip_group_tailq, spdk_iip_group_impl);
TAILQ_HEAD(iip_rx_tailq, spdk_iip_rx_seg);

enum spdk_iip_sock_type {
	SPDK_IIP_SOCK_LISTEN,
	SPDK_IIP_SOCK_STREAM,
};

struct spdk_iip_rx_seg {
	uint8_t				*buf;
	size_t				len;
	size_t				off;
	TAILQ_ENTRY(spdk_iip_rx_seg)	link;
};

struct spdk_iip_sock {
	struct spdk_sock		base;
	enum spdk_iip_sock_type		type;
	uint32_t			local_ip_be;
	uint32_t			peer_ip_be;
	uint16_t			local_port_be;
	uint16_t			peer_port_be;
	uint8_t				local_mac[RTE_ETHER_ADDR_LEN];
	uint8_t				peer_mac[RTE_ETHER_ADDR_LEN];
	void				*tcp_handle;
	struct spdk_iip_group_impl	*owner_group;
	struct spdk_iip_sock		*listener;
	bool				connected;
	bool				closed;
	bool				closing;
	bool				ready_queued;
	int				recvlowat;
	struct iip_rx_tailq		rxq;
	size_t				rxq_bytes;
	struct iip_sock_tailq		pending_accepts;
	TAILQ_ENTRY(spdk_iip_sock)	link;
	TAILQ_ENTRY(spdk_iip_sock)	ready_link;
	TAILQ_ENTRY(spdk_iip_sock)	pending_link;
};

struct spdk_iip_group_impl {
	struct spdk_sock_group_impl	base;
	uint16_t			portid;
	uint16_t			queueid;
	uint16_t			socketid;
	uint32_t			local_ip_be;
	uint8_t				local_mac[RTE_ETHER_ADDR_LEN];
	void				*workspace;
	struct rte_mempool		*mbuf_pool;
	struct rte_mempool		*clone_mbuf_pool;
	struct rte_mbuf			*tx[IIP_SOCK_TX_BATCH];
	uint16_t			tx_cnt;
	uint32_t			active_sock_count;
	struct iip_sock_tailq		ready_socks;
	TAILQ_ENTRY(spdk_iip_group_impl) link;
};

struct spdk_iip_global {
	pthread_mutex_t			lock;
	bool				port_initialized;
	uint16_t			portid;
	uint16_t			num_queues;
	uint32_t			local_ip_be;
	uint8_t				local_mac[RTE_ETHER_ADDR_LEN];
	struct rte_mempool		*mbuf_pool[RTE_MAX_LCORE];
	struct rte_mempool		*clone_mbuf_pool[RTE_MAX_LCORE];
	struct rte_eth_conf		port_conf;
	struct rte_eth_dev_info		dev_info;
	struct iip_group_tailq		groups;
	struct iip_sock_tailq		listeners;
};

static struct spdk_iip_global g_iip = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.portid = 0,
};

static struct spdk_sock_impl_opts g_iip_impl_opts = {
	.recv_buf_size = DEFAULT_SO_RCVBUF_SIZE,
	.send_buf_size = DEFAULT_SO_SNDBUF_SIZE,
	.enable_recv_pipe = false,
	.enable_quickack = false,
	.enable_placement_id = PLACEMENT_NONE,
	.enable_zerocopy_send_server = false,
	.enable_zerocopy_send_client = false,
	.zerocopy_threshold = 0,
	.tls_version = 0,
	.enable_ktls = false,
	.psk_key = NULL,
	.psk_key_size = 0,
	.psk_identity = NULL,
	.get_key = NULL,
	.get_key_ctx = NULL,
	.tls_cipher_suites = NULL
};

#define __iip_sock(sock) ((struct spdk_iip_sock *)(sock))
#define __iip_group(group) ((struct spdk_iip_group_impl *)(group))

static const char *
iip_sock_ip4_str(uint32_t ip_be, char *buf, size_t len)
{
	if (inet_ntop(AF_INET, &ip_be, buf, len) == NULL) {
		snprintf(buf, len, "invalid");
	}

	return buf;
}

#ifdef IIP_SOCK_ENABLE_TRACE_LOG
static void
iip_sock_trace_tcp_pkt(struct spdk_iip_group_impl *group, struct rte_mbuf *m, const char *dir)
{
	void *opaque = group;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	uint16_t ethertype;
	uint16_t ip_hlen;
	uint16_t tcp_hlen;
	uint16_t ip_len;

	if (group == NULL || m == NULL ||
	    rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr) + sizeof(struct iip_ip4_hdr)) {
		return;
	}

	ethertype = iip_ops_l2_ethertype_be(m, opaque);
	if (ntohs(ethertype) != RTE_ETHER_TYPE_IPV4 || (PB_IP4(m)->vl >> 4) != 4 ||
	    PB_IP4(m)->proto != 6) {
		return;
	}

	ip_hlen = (PB_IP4(m)->vl & 0x0f) * 4;
	if (ip_hlen < sizeof(struct iip_ip4_hdr) ||
	    rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr) + ip_hlen + sizeof(struct iip_tcp_hdr)) {
		return;
	}

	tcp_hlen = PB_TCP_HDR_LEN(m) * 4;
	ip_len = __iip_ntohs(PB_IP4(m)->len_be);
	if (tcp_hlen < sizeof(struct iip_tcp_hdr) || ip_len < ip_hlen + tcp_hlen) {
		return;
	}

	SPDK_NOTICELOG("iip %s tcp queue=%u len=%u src=%s:%u dst=%s:%u syn=%u ack=%u psh=%u fin=%u rst=%u seq=%u ackseq=%u payload=%u\n",
		       dir, group->queueid, rte_pktmbuf_data_len(m),
		       iip_sock_ip4_str(PB_IP4(m)->src_be, src_ip, sizeof(src_ip)),
		       ntohs(PB_TCP(m)->src_be),
		       iip_sock_ip4_str(PB_IP4(m)->dst_be, dst_ip, sizeof(dst_ip)),
		       ntohs(PB_TCP(m)->dst_be),
		       PB_TCP_HDR_HAS_SYN(m), PB_TCP_HDR_HAS_ACK(m), PB_TCP_HDR_HAS_PSH(m),
		       PB_TCP_HDR_HAS_FIN(m), PB_TCP_HDR_HAS_RST(m),
		       __iip_ntohl(PB_TCP(m)->seq_be), __iip_ntohl(PB_TCP(m)->ack_seq_be),
		       ip_len - ip_hlen - tcp_hlen);
}
#endif

static void
iip_sock_global_lists_init(void)
{
	if (g_iip.groups.tqh_last == NULL) {
		TAILQ_INIT(&g_iip.groups);
	}
	if (g_iip.listeners.tqh_last == NULL) {
		TAILQ_INIT(&g_iip.listeners);
	}
}

static void
iip_ops_util_now_ns(uint32_t t[3], void *opaque)
{
	struct timespec ts;

	(void)opaque;
	clock_gettime(CLOCK_REALTIME, &ts);
	t[0] = (ts.tv_sec >> 32) & 0xffffffffu;
	t[1] = ts.tv_sec & 0xffffffffu;
	t[2] = ts.tv_nsec;
}

static int
iip_sock_copy_impl_opts(struct spdk_sock_impl_opts *dst,
			const struct spdk_sock_impl_opts *src, size_t len)
{
#define IIP_IMPL_OPT_COPY(field) \
	do { \
		if (offsetof(struct spdk_sock_impl_opts, field) + sizeof(src->field) <= len) { \
			dst->field = src->field; \
		} \
	} while (0)

	IIP_IMPL_OPT_COPY(recv_buf_size);
	IIP_IMPL_OPT_COPY(send_buf_size);
	IIP_IMPL_OPT_COPY(enable_recv_pipe);
	IIP_IMPL_OPT_COPY(enable_quickack);
	IIP_IMPL_OPT_COPY(enable_placement_id);
	IIP_IMPL_OPT_COPY(enable_zerocopy_send_server);
	IIP_IMPL_OPT_COPY(enable_zerocopy_send_client);
	IIP_IMPL_OPT_COPY(zerocopy_threshold);
	IIP_IMPL_OPT_COPY(tls_version);
	IIP_IMPL_OPT_COPY(enable_ktls);
	IIP_IMPL_OPT_COPY(psk_key);
	IIP_IMPL_OPT_COPY(psk_key_size);
	IIP_IMPL_OPT_COPY(psk_identity);
	IIP_IMPL_OPT_COPY(get_key);
	IIP_IMPL_OPT_COPY(get_key_ctx);
	IIP_IMPL_OPT_COPY(tls_cipher_suites);

#undef IIP_IMPL_OPT_COPY
	return 0;
}

static int
iip_sock_impl_get_opts(struct spdk_sock_impl_opts *opts, size_t *len)
{
	size_t copy_len;

	if (opts == NULL || len == NULL) {
		errno = EINVAL;
		return -1;
	}

	copy_len = spdk_min(*len, sizeof(g_iip_impl_opts));
	memset(opts, 0, *len);
	memcpy(opts, &g_iip_impl_opts, copy_len);
	*len = copy_len;
	return 0;
}

static int
iip_sock_impl_set_opts(const struct spdk_sock_impl_opts *opts, size_t len)
{
	if (opts == NULL) {
		errno = EINVAL;
		return -1;
	}

	return iip_sock_copy_impl_opts(&g_iip_impl_opts, opts, len);
}

static struct spdk_iip_sock *
iip_sock_find_listener(uint32_t local_ip_be, uint16_t local_port_be)
{
	struct spdk_iip_sock *sock;

	TAILQ_FOREACH(sock, &g_iip.listeners, link) {
		if (sock->local_port_be != local_port_be) {
			continue;
		}
		if (sock->local_ip_be == 0 || sock->local_ip_be == local_ip_be) {
			return sock;
		}
	}

	return NULL;
}

static void
iip_sock_queue_ready(struct spdk_iip_sock *sock)
{
	struct spdk_iip_group_impl *group = sock->owner_group;

	if (group == NULL || sock->ready_queued) {
		return;
	}

	sock->ready_queued = true;
	TAILQ_INSERT_TAIL(&group->ready_socks, sock, ready_link);
}

static void
iip_sock_unqueue_ready(struct spdk_iip_sock *sock)
{
	struct spdk_iip_group_impl *group = sock->owner_group;

	if (!sock->ready_queued) {
		return;
	}

	if (group != NULL) {
		TAILQ_REMOVE(&group->ready_socks, sock, ready_link);
	}
	sock->ready_queued = false;
}

static void
iip_sock_rxq_free(struct spdk_iip_sock *sock)
{
	struct spdk_iip_rx_seg *seg;

	while ((seg = TAILQ_FIRST(&sock->rxq)) != NULL) {
		TAILQ_REMOVE(&sock->rxq, seg, link);
		free(seg->buf);
		free(seg);
	}

	sock->rxq_bytes = 0;
}

static int
iip_sock_enqueue_payload(struct spdk_iip_sock *sock, const void *buf, size_t len)
{
	struct spdk_iip_rx_seg *seg;

	if (len == 0) {
		return 0;
	}

	seg = calloc(1, sizeof(*seg));
	if (seg == NULL) {
		return -ENOMEM;
	}

	seg->buf = malloc(len);
	if (seg->buf == NULL) {
		free(seg);
		return -ENOMEM;
	}

	memcpy(seg->buf, buf, len);
	seg->len = len;
	TAILQ_INSERT_TAIL(&sock->rxq, seg, link);
	sock->rxq_bytes += len;
	iip_sock_queue_ready(sock);

	return 0;
}

static int
iip_sock_alloc_stack_objs(struct spdk_iip_group_impl *group)
{
	uint32_t i;

	group->workspace = rte_zmalloc(NULL, iip_workspace_size(), 8);
	if (group->workspace == NULL) {
		return -ENOMEM;
	}

	for (i = 0; i < IIP_SOCK_NETSTACK_PB; i++) {
		void *pb = rte_zmalloc(NULL, iip_pb_size(), 8);

		if (pb == NULL) {
			return -ENOMEM;
		}
		iip_add_pb(group->workspace, pb);
	}

	for (i = 0; i < IIP_SOCK_NETSTACK_TCP_CONN; i++) {
		void *conn = rte_zmalloc(NULL, iip_tcp_conn_size(), 8);

		if (conn == NULL) {
			return -ENOMEM;
		}
		iip_add_tcp_conn(group->workspace, conn);
	}

	return 0;
}

static void
iip_sock_global_port_cleanup_pools(void)
{
	uint16_t q;

	for (q = 0; q < RTE_MAX_LCORE; q++) {
		if (g_iip.clone_mbuf_pool[q] != NULL) {
			rte_mempool_free(g_iip.clone_mbuf_pool[q]);
			g_iip.clone_mbuf_pool[q] = NULL;
		}
		if (g_iip.mbuf_pool[q] != NULL) {
			rte_mempool_free(g_iip.mbuf_pool[q]);
			g_iip.mbuf_pool[q] = NULL;
		}
	}
}

static int
iip_sock_global_port_init(void)
{
	struct rte_eth_conf conf = {0};
	struct rte_eth_dev_info dev_info = {0};
	uint16_t nb_rxd = IIP_SOCK_RX_DESC;
	uint16_t nb_txd = IIP_SOCK_TX_DESC;
	uint16_t q;
	int rc;

	if (g_iip.port_initialized) {
		return 0;
	}

	if (TAILQ_EMPTY(&g_iip.groups)) {
		return 0;
	}

	if (rte_eth_dev_count_avail() == 0 || g_iip.portid >= RTE_MAX_ETHPORTS) {
		SPDK_ERRLOG("iip sock requires an available DPDK ethdev\n");
		return -ENODEV;
	}

	rc = rte_eth_dev_info_get(g_iip.portid, &dev_info);
	if (rc < 0) {
		SPDK_ERRLOG("rte_eth_dev_info_get(%u) failed: %d\n", g_iip.portid, rc);
		return rc;
	}

	g_iip.num_queues = spdk_min((uint16_t)spdk_env_get_core_count(), dev_info.max_rx_queues);
	g_iip.num_queues = spdk_min(g_iip.num_queues, dev_info.max_tx_queues);
	if (g_iip.num_queues == 0) {
		return -ENODEV;
	}

	conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
	conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
	if (dev_info.flow_type_rss_offloads & RTE_ETH_RSS_TCP) {
		conf.rx_adv_conf.rss_conf.rss_hf |= RTE_ETH_RSS_TCP & dev_info.flow_type_rss_offloads;
	} else if (g_iip.num_queues > 1) {
		SPDK_ERRLOG("iip sock multi-queue mode requires TCP RSS support\n");
		return -ENOTSUP;
	}
	if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) {
		conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) {
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) {
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) {
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO) {
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_TSO;
	}
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) {
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
	}
#if RTE_ETH_TX_OFFLOAD_UDP_TSO
	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_TSO) {
		conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_TSO;
	}
#endif

	rc = rte_eth_dev_configure(g_iip.portid, g_iip.num_queues, g_iip.num_queues, &conf);
	if (rc < 0) {
		SPDK_ERRLOG("rte_eth_dev_configure(%u) failed: %d\n", g_iip.portid, rc);
		return rc;
	}

	rc = rte_eth_dev_adjust_nb_rx_tx_desc(g_iip.portid, &nb_rxd, &nb_txd);
	if (rc < 0) {
		return rc;
	}

	for (q = 0; q < g_iip.num_queues; q++) {
		char pool_name[RTE_MEMPOOL_NAMESIZE];
		char clone_pool_name[RTE_MEMPOOL_NAMESIZE];
		int socket_id = rte_eth_dev_socket_id(g_iip.portid);
		snprintf(pool_name, sizeof(pool_name), "iip_sock_%u_%u", g_iip.portid, q);
		snprintf(clone_pool_name, sizeof(clone_pool_name), "iip_sock_clone_%u_%u", g_iip.portid, q);
		uint32_t pool_size = nb_rxd + nb_txd + 1024;
		uint32_t clone_pool_size;

		if (socket_id < 0) {
			SPDK_NOTICELOG("iip sock DPDK port %u has no NUMA socket; using SOCKET_ID_ANY\n",
				       g_iip.portid);
			socket_id = SOCKET_ID_ANY;
		}

		if (pool_size < 8192U) {
			pool_size = 8192U;
		}
		clone_pool_size = pool_size * 4;
		if (clone_pool_size < 32768U) {
			clone_pool_size = 32768U;
		}

		g_iip.mbuf_pool[q] = rte_pktmbuf_pool_create(pool_name, pool_size,
				IIP_SOCK_MBUF_CACHE_SIZE, 0, IIP_SOCK_MBUF_DATA_ROOM,
				socket_id);
			if (g_iip.mbuf_pool[q] == NULL) {
				SPDK_ERRLOG("rte_pktmbuf_pool_create(%s, count=%u, data_room=%u, socket=%d) failed: %s (%d)\n",
					    pool_name, pool_size, IIP_SOCK_MBUF_DATA_ROOM, socket_id,
					    rte_strerror(rte_errno), rte_errno);
				iip_sock_global_port_cleanup_pools();
				return -ENOMEM;
			}

		g_iip.clone_mbuf_pool[q] = rte_pktmbuf_pool_create(clone_pool_name, clone_pool_size,
				IIP_SOCK_MBUF_CACHE_SIZE, 0, IIP_SOCK_CLONE_MBUF_DATA_ROOM,
				socket_id);
			if (g_iip.clone_mbuf_pool[q] == NULL) {
				SPDK_ERRLOG("rte_pktmbuf_pool_create(%s, count=%u, data_room=%u, socket=%d) failed: %s (%d)\n",
					    clone_pool_name, clone_pool_size, IIP_SOCK_CLONE_MBUF_DATA_ROOM, socket_id,
					    rte_strerror(rte_errno), rte_errno);
				iip_sock_global_port_cleanup_pools();
				return -ENOMEM;
			}

			rc = rte_eth_rx_queue_setup(g_iip.portid, q, nb_rxd, socket_id,
						    &dev_info.default_rxconf, g_iip.mbuf_pool[q]);
			if (rc < 0) {
				iip_sock_global_port_cleanup_pools();
				return rc;
			}

			rc = rte_eth_tx_queue_setup(g_iip.portid, q, nb_txd, socket_id,
						    &dev_info.default_txconf);
			if (rc < 0) {
				iip_sock_global_port_cleanup_pools();
				return rc;
			}
	}

	rc = rte_eth_dev_start(g_iip.portid);
	if (rc < 0) {
		iip_sock_global_port_cleanup_pools();
		return rc;
	}

	if (rte_eth_promiscuous_enable(g_iip.portid) < 0) {
		SPDK_NOTICELOG("iip sock could not enable promiscuous mode on port %u\n", g_iip.portid);
	}

	rc = rte_eth_macaddr_get(g_iip.portid, (struct rte_ether_addr *)g_iip.local_mac);
	if (rc < 0) {
		rte_eth_dev_stop(g_iip.portid);
		iip_sock_global_port_cleanup_pools();
		return rc;
	}

	g_iip.port_conf = conf;
	g_iip.dev_info = dev_info;
	g_iip.port_initialized = true;

	SPDK_NOTICELOG("iip sock initialized DPDK port %u with %u queues\n",
		       g_iip.portid, g_iip.num_queues);
	return 0;
}

static int
iip_sock_group_refresh_config(struct spdk_iip_group_impl *group)
{
	int rc;

	pthread_mutex_lock(&g_iip.lock);
	rc = iip_sock_global_port_init();
	if (rc == 0) {
		group->portid = g_iip.portid;
		group->local_ip_be = g_iip.local_ip_be;
		memcpy(group->local_mac, g_iip.local_mac, sizeof(group->local_mac));
		if (group->queueid < g_iip.num_queues) {
			group->mbuf_pool = g_iip.mbuf_pool[group->queueid];
			group->clone_mbuf_pool = g_iip.clone_mbuf_pool[group->queueid];
		}
	}
	pthread_mutex_unlock(&g_iip.lock);

	return rc;
}

static int
iip_sock_group_poll_rx(struct spdk_iip_group_impl *group)
{
	struct rte_mbuf *mbufs[IIP_SOCK_RX_BATCH];
	uint16_t cnt;
	uint32_t next_us;

	if (!g_iip.port_initialized || group->queueid >= g_iip.num_queues) {
		return 0;
	}

	cnt = rte_eth_rx_burst(group->portid, group->queueid, mbufs, IIP_SOCK_RX_BATCH);
#ifdef IIP_SOCK_ENABLE_TRACE_LOG
	for (uint16_t i = 0; i < cnt; i++) {
		iip_sock_trace_tcp_pkt(group, mbufs[i], "rx");
	}
#endif
	iip_run(group->workspace, group->local_mac, group->local_ip_be,
		(void **)mbufs, cnt, &next_us, group);
	(void)next_us;
	return cnt;
}

static int
iip_sock_poll_idle_groups_for_accept(void)
{
	struct spdk_iip_group_impl *group;
	int rc = 0;

	pthread_mutex_lock(&g_iip.lock);
	TAILQ_FOREACH(group, &g_iip.groups, link) {
		if (group->active_sock_count != 0) {
			continue;
		}
		pthread_mutex_unlock(&g_iip.lock);
		(void)iip_sock_group_refresh_config(group);
		rc += iip_sock_group_poll_rx(group);
		pthread_mutex_lock(&g_iip.lock);
	}
	pthread_mutex_unlock(&g_iip.lock);

	return rc;
}

static void *
iip_ops_pkt_alloc(void *opaque)
{
	struct spdk_iip_group_impl *group = opaque;

	assert(group != NULL);
	assert(group->mbuf_pool != NULL);
	return rte_pktmbuf_alloc(group->mbuf_pool);
}

static void
iip_ops_pkt_free(void *pkt, void *opaque)
{
	(void)opaque;
	rte_pktmbuf_free(pkt);
}

static void *
iip_ops_pkt_get_data(void *pkt, void *opaque)
{
	(void)opaque;
	return rte_pktmbuf_mtod((struct rte_mbuf *)pkt, void *);
}

static uint16_t
iip_ops_pkt_get_len(void *pkt, void *opaque)
{
	(void)opaque;
	return rte_pktmbuf_data_len((struct rte_mbuf *)pkt);
}

static void
iip_ops_pkt_set_len(void *pkt, uint16_t len, void *opaque)
{
	struct rte_mbuf *m = pkt;

	(void)opaque;
	m->data_len = len;
	m->pkt_len = len;
}

static void
iip_ops_pkt_increment_head(void *pkt, uint16_t len, void *opaque)
{
	(void)opaque;
	rte_pktmbuf_adj(pkt, len);
}

static void
iip_ops_pkt_decrement_tail(void *pkt, uint16_t len, void *opaque)
{
	(void)opaque;
	rte_pktmbuf_trim(pkt, len);
}

static void *
iip_ops_pkt_clone(void *pkt, void *opaque)
{
	struct spdk_iip_group_impl *group = opaque;
	struct rte_mbuf *src = pkt;
	struct rte_mbuf *clone;
	struct rte_mbuf *seg;
	uint8_t *dst;
	uint32_t len;

	assert(group != NULL);
	assert(group->clone_mbuf_pool != NULL);
	assert(pkt != NULL);

	clone = rte_pktmbuf_clone(src, group->clone_mbuf_pool);
	if (clone != NULL) {
		return clone;
	}

	len = rte_pktmbuf_pkt_len(src);
	if (len == 0) {
		len = rte_pktmbuf_data_len(src);
	}

	clone = rte_pktmbuf_alloc(group->mbuf_pool);
	if (clone == NULL || len > rte_pktmbuf_tailroom(clone)) {
		SPDK_NOTICELOG("iip pkt clone failed queue=%u len=%u clone_avail=%u clone_in_use=%u data_avail=%u data_in_use=%u rte_errno=%d\n",
			       group->queueid, len,
			       rte_mempool_avail_count(group->clone_mbuf_pool),
			       rte_mempool_in_use_count(group->clone_mbuf_pool),
			       rte_mempool_avail_count(group->mbuf_pool),
			       rte_mempool_in_use_count(group->mbuf_pool), rte_errno);
		if (clone != NULL) {
			rte_pktmbuf_free(clone);
		}
		return NULL;
	}

	dst = rte_pktmbuf_mtod(clone, uint8_t *);
	for (seg = src; seg != NULL; seg = seg->next) {
		uint16_t seg_len = rte_pktmbuf_data_len(seg);

		memcpy(dst, rte_pktmbuf_mtod(seg, const void *), seg_len);
		dst += seg_len;
	}

	clone->data_len = len;
	clone->pkt_len = len;
	clone->nb_segs = 1;
	clone->ol_flags = src->ol_flags;
	clone->l2_len = src->l2_len;
	clone->l3_len = src->l3_len;
	clone->l4_len = src->l4_len;
	return clone;
}

static void
iip_ops_pkt_scatter_gather_chain_append(void *pkt_head, void *pkt_tail, void *opaque)
{
	(void)opaque;
	assert(rte_pktmbuf_chain(pkt_head, pkt_tail) == 0);
}

static void *
iip_ops_pkt_scatter_gather_chain_get_next(void *pkt_head, void *opaque)
{
	(void)opaque;
	return ((struct rte_mbuf *)pkt_head)->next;
}

static uint16_t
iip_ops_l2_hdr_len(void *pkt, void *opaque)
{
	(void)pkt;
	(void)opaque;
	return sizeof(struct rte_ether_hdr);
}

static uint8_t *
iip_ops_l2_hdr_src_ptr(void *pkt, void *opaque)
{
	return ((struct rte_ether_hdr *)iip_ops_pkt_get_data(pkt, opaque))->src_addr.addr_bytes;
}

static uint8_t *
iip_ops_l2_hdr_dst_ptr(void *pkt, void *opaque)
{
	return ((struct rte_ether_hdr *)iip_ops_pkt_get_data(pkt, opaque))->dst_addr.addr_bytes;
}

static uint16_t
iip_ops_l2_ethertype_be(void *pkt, void *opaque)
{
	return ((struct rte_ether_hdr *)iip_ops_pkt_get_data(pkt, opaque))->ether_type;
}

static uint16_t
iip_ops_l2_addr_len(void *opaque)
{
	(void)opaque;
	return RTE_ETHER_ADDR_LEN;
}

static void
iip_ops_l2_broadcast_addr(uint8_t bc_mac[], void *opaque)
{
	(void)opaque;
	memset(bc_mac, 0xff, RTE_ETHER_ADDR_LEN);
}

static void
iip_ops_l2_hdr_craft(void *pkt, uint8_t src[], uint8_t dst[], uint16_t ethertype_be,
		     void *opaque)
{
	struct rte_ether_hdr *ethh = iip_ops_pkt_get_data(pkt, opaque);

	memcpy(ethh->src_addr.addr_bytes, src, RTE_ETHER_ADDR_LEN);
	memcpy(ethh->dst_addr.addr_bytes, dst, RTE_ETHER_ADDR_LEN);
	ethh->ether_type = ethertype_be;
}

static uint8_t
iip_ops_l2_skip(void *pkt, void *opaque)
{
	(void)pkt;
	(void)opaque;
	return 0;
}

static uint8_t
iip_ops_arp_lhw(void *opaque)
{
	(void)opaque;
	return RTE_ETHER_ADDR_LEN;
}

static uint8_t
iip_ops_arp_lproto(void *opaque)
{
	(void)opaque;
	return sizeof(uint32_t);
}

static void
iip_ops_l2_flush(void *opaque)
{
	struct spdk_iip_group_impl *group = opaque;
	uint16_t prepared, sent, i;

	if (group == NULL || group->tx_cnt == 0) {
		return;
	}

	prepared = rte_eth_tx_prepare(group->portid, group->queueid, group->tx, group->tx_cnt);
	sent = rte_eth_tx_burst(group->portid, group->queueid, group->tx, prepared);
	for (i = sent; i < group->tx_cnt; i++) {
		rte_pktmbuf_free(group->tx[i]);
	}
	group->tx_cnt = 0;
}

static void
iip_ops_l2_push(void *pkt, void *opaque)
{
	struct spdk_iip_group_impl *group = opaque;
	struct rte_mbuf *m = pkt;

	if (group == NULL || pkt == NULL) {
		if (group != NULL) {
			SPDK_NOTICELOG("iip drop null tx packet queue=%u clone_avail=%u clone_in_use=%u data_avail=%u data_in_use=%u\n",
				       group->queueid,
				       group->clone_mbuf_pool == NULL ? 0 : rte_mempool_avail_count(group->clone_mbuf_pool),
				       group->clone_mbuf_pool == NULL ? 0 : rte_mempool_in_use_count(group->clone_mbuf_pool),
				       group->mbuf_pool == NULL ? 0 : rte_mempool_avail_count(group->mbuf_pool),
				       group->mbuf_pool == NULL ? 0 : rte_mempool_in_use_count(group->mbuf_pool));
		}
		return;
	}

	m->pkt_len = 0;
	for (; m != NULL; m = m->next) {
		((struct rte_mbuf *)pkt)->pkt_len += m->data_len;
	}

	group->tx[group->tx_cnt++] = pkt;
#ifdef IIP_SOCK_ENABLE_TRACE_LOG
	iip_sock_trace_tcp_pkt(group, pkt, "tx");
#endif
	if (group->tx_cnt == IIP_SOCK_TX_BATCH) {
		iip_ops_l2_flush(opaque);
	}
}

static uint8_t
iip_ops_nic_feature_offload_tx_scatter_gather(void *opaque)
{
	(void)opaque;
	return 0;
}

static uint8_t
iip_ops_nic_feature_offload_ip4_rx_checksum(void *opaque)
{
	(void)opaque;
	return (g_iip.port_conf.rxmode.offloads & RTE_ETH_RX_OFFLOAD_CHECKSUM) ? 1 : 0;
}

static uint8_t
iip_ops_nic_feature_offload_ip4_tx_checksum(void *opaque)
{
	(void)opaque;
	return (g_iip.port_conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) ? 1 : 0;
}

static uint8_t
iip_ops_nic_feature_offload_tcp_rx_checksum(void *opaque)
{
	return iip_ops_nic_feature_offload_ip4_rx_checksum(opaque);
}

static uint8_t
iip_ops_nic_feature_offload_tcp_tx_checksum(void *opaque)
{
	(void)opaque;
	return (g_iip.port_conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) ? 1 : 0;
}

static uint8_t
iip_ops_nic_feature_offload_tcp_tx_tso(void *opaque)
{
	(void)opaque;
	return (g_iip.port_conf.txmode.offloads & RTE_ETH_TX_OFFLOAD_TCP_TSO) ? 1 : 0;
}

static uint8_t
iip_ops_nic_feature_offload_udp_rx_checksum(void *opaque)
{
	return iip_ops_nic_feature_offload_ip4_rx_checksum(opaque);
}

static uint8_t
iip_ops_nic_feature_offload_udp_tx_checksum(void *opaque)
{
	(void)opaque;
	return 0;
}

static uint8_t
iip_ops_nic_feature_offload_udp_tx_tso(void *opaque)
{
	(void)opaque;
	return 0;
}

static uint8_t
iip_ops_nic_offload_ip4_rx_checksum(void *m, void *opaque)
{
	(void)opaque;
	return (((struct rte_mbuf *)m)->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_GOOD) ? 1 : 0;
}

static uint8_t
iip_ops_nic_offload_tcp_rx_checksum(void *m, void *opaque)
{
	(void)opaque;
	return (((struct rte_mbuf *)m)->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_GOOD) ? 1 : 0;
}

static uint8_t
iip_ops_nic_offload_udp_rx_checksum(void *m, void *opaque)
{
	return iip_ops_nic_offload_tcp_rx_checksum(m, opaque);
}

static void
iip_ops_nic_offload_ip4_tx_checksum_mark(void *m, void *opaque)
{
	struct rte_mbuf *mbuf = m;

	(void)opaque;
	mbuf->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
	mbuf->l2_len = sizeof(struct rte_ether_hdr);
	mbuf->l3_len = (PB_IP4(m)->vl & 0x0f) * 4;
}

static void
iip_ops_nic_offload_tcp_tx_checksum_mark(void *m, void *opaque)
{
	(void)opaque;
	((struct rte_mbuf *)m)->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
}

static void
iip_ops_nic_offload_tcp_tx_tso_mark(void *m, void *opaque)
{
	struct rte_mbuf *mbuf = m;
	uint16_t hdr_len = (PB_IP4(m)->vl & 0x0f) * 4 + PB_TCP_HDR_LEN(m) * 4;

	(void)opaque;
	if (1500 - hdr_len < PB_TCP_PAYLOAD_LEN(m)) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
		mbuf->l4_len = PB_TCP_HDR_LEN(m) * 4;
		mbuf->tso_segsz = 1500 - hdr_len;
	}
}

static void
iip_ops_nic_offload_udp_tx_checksum_mark(void *m, void *opaque)
{
	(void)opaque;
	((struct rte_mbuf *)m)->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
}

static void
iip_ops_nic_offload_udp_tx_tso_mark(void *m, void *opaque)
{
	struct rte_mbuf *mbuf = m;
	uint16_t hdr_len = (PB_IP4(m)->vl & 0x0f) * 4 + sizeof(struct iip_udp_hdr);

	(void)opaque;
	if (RTE_MBUF_F_TX_UDP_SEG && (uint16_t)(1500 - hdr_len) < PB_UDP_PAYLOAD_LEN(m)) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_SEG;
		mbuf->l4_len = sizeof(struct iip_udp_hdr);
		mbuf->tso_segsz = 1500 - hdr_len;
	}
}

static void
iip_ops_arp_reply(void *mem, void *m, void *opaque)
{
	(void)mem;
	(void)m;
	(void)opaque;
}

static void
iip_ops_icmp_reply(void *mem, void *m, void *opaque)
{
	(void)mem;
	(void)m;
	(void)opaque;
}

static uint8_t
iip_ops_tcp_accept(void *mem, void *m, void *opaque)
{
	struct spdk_iip_sock *listener;

	(void)mem;
	(void)opaque;

	pthread_mutex_lock(&g_iip.lock);
	listener = iip_sock_find_listener(PB_IP4(m)->dst_be, PB_TCP(m)->dst_be);
	pthread_mutex_unlock(&g_iip.lock);

	return listener != NULL;
}

static void *
iip_ops_tcp_accepted(void *mem, void *handle, void *m, void *opaque)
{
	struct spdk_iip_group_impl *group = opaque;
	struct spdk_iip_sock *listener, *sock;
	char local_ip[INET_ADDRSTRLEN];
	char peer_ip[INET_ADDRSTRLEN];

	(void)mem;

	sock = calloc(1, sizeof(*sock));
	if (sock == NULL) {
		return NULL;
	}

	sock->type = SPDK_IIP_SOCK_STREAM;
	sock->tcp_handle = handle;
	sock->owner_group = group;
	sock->connected = true;
	sock->recvlowat = 1;
	sock->local_ip_be = PB_IP4(m)->dst_be;
	sock->peer_ip_be = PB_IP4(m)->src_be;
	sock->local_port_be = PB_TCP(m)->dst_be;
	sock->peer_port_be = PB_TCP(m)->src_be;
	memcpy(sock->local_mac, iip_ops_l2_hdr_dst_ptr(m, opaque), sizeof(sock->local_mac));
	memcpy(sock->peer_mac, iip_ops_l2_hdr_src_ptr(m, opaque), sizeof(sock->peer_mac));
	TAILQ_INIT(&sock->rxq);
	TAILQ_INIT(&sock->pending_accepts);

	pthread_mutex_lock(&g_iip.lock);
	listener = iip_sock_find_listener(sock->local_ip_be, sock->local_port_be);
	if (listener == NULL) {
		pthread_mutex_unlock(&g_iip.lock);
		SPDK_NOTICELOG("iip accepted no listener sock=%p handle=%p group=%p local=%s:%u peer=%s:%u\n",
			       sock, handle, group,
			       iip_sock_ip4_str(sock->local_ip_be, local_ip, sizeof(local_ip)),
			       ntohs(sock->local_port_be),
			       iip_sock_ip4_str(sock->peer_ip_be, peer_ip, sizeof(peer_ip)),
			       ntohs(sock->peer_port_be));
		free(sock);
		return NULL;
	}

	sock->listener = listener;
	TAILQ_INSERT_TAIL(&listener->pending_accepts, sock, pending_link);
	pthread_mutex_unlock(&g_iip.lock);

	IIP_SOCK_TRACELOG("iip accepted sock=%p handle=%p group=%p queue=%u listener=%p local=%s:%u peer=%s:%u\n",
			  sock, handle, group, group == NULL ? UINT16_MAX : group->queueid, listener,
			  iip_sock_ip4_str(sock->local_ip_be, local_ip, sizeof(local_ip)),
			  ntohs(sock->local_port_be),
			  iip_sock_ip4_str(sock->peer_ip_be, peer_ip, sizeof(peer_ip)),
			  ntohs(sock->peer_port_be));
	return sock;
}

static void *
iip_ops_tcp_connected(void *mem, void *handle, void *m, void *opaque)
{
	(void)mem;
	(void)handle;
	(void)m;
	(void)opaque;
	return NULL;
}

static void
iip_ops_tcp_payload(void *mem, void *handle, void *m, void *tcp_opaque,
		    uint16_t head_off, uint16_t tail_off, void *opaque)
{
	struct spdk_iip_sock *sock = tcp_opaque;
	uint16_t payload_len;
	size_t app_len;

	if (sock == NULL) {
		SPDK_NOTICELOG("iip payload without sock handle=%p group=%p\n", handle, opaque);
		return;
	}

	payload_len = PB_TCP_PAYLOAD_LEN(m);
	app_len = payload_len >= head_off + tail_off ? payload_len - head_off - tail_off : 0;
	IIP_SOCK_TRACELOG("iip payload sock=%p handle=%p owner=%p connected=%d closed=%d payload=%u app=%zu head=%u tail=%u flags syn=%u ack=%u fin=%u rst=%u rxq=%zu\n",
			  sock, handle, sock->owner_group, sock->connected, sock->closed,
			  payload_len, app_len, head_off, tail_off,
			  PB_TCP_HDR_HAS_SYN(m), PB_TCP_HDR_HAS_ACK(m),
			  PB_TCP_HDR_HAS_FIN(m), PB_TCP_HDR_HAS_RST(m), sock->rxq_bytes);
	if (payload_len >= head_off + tail_off) {
		(void)iip_sock_enqueue_payload(sock, PB_TCP_PAYLOAD(m) + head_off,
					       payload_len - head_off - tail_off);
	}

	iip_tcp_rxbuf_consumed(mem, handle, 1, opaque);
}

static void
iip_ops_tcp_acked(void *mem, void *handle, void *m, void *tcp_opaque, void *opaque)
{
	(void)mem;
	(void)handle;
	(void)m;
	(void)tcp_opaque;
	(void)opaque;
}

static void
iip_ops_tcp_closed(void *handle, uint8_t local_mac[], uint32_t local_ip4_be,
		   uint16_t local_port_be, uint8_t peer_mac[], uint32_t peer_ip4_be,
		   uint16_t peer_port_be, void *tcp_opaque, void *opaque)
{
	struct spdk_iip_sock *sock = tcp_opaque;
	char local_ip[INET_ADDRSTRLEN];
	char peer_ip[INET_ADDRSTRLEN];

	(void)handle;
	(void)local_mac;
	(void)local_ip4_be;
	(void)local_port_be;
	(void)peer_mac;
	(void)peer_ip4_be;
	(void)peer_port_be;
	(void)opaque;

	if (sock != NULL) {
			IIP_SOCK_TRACELOG("iip tcp closed sock=%p handle=%p owner=%p connected=%d closed=%d local=%s:%u peer=%s:%u\n",
					  sock, handle, sock->owner_group, sock->connected, sock->closed,
					  iip_sock_ip4_str(local_ip4_be, local_ip, sizeof(local_ip)),
					  ntohs(local_port_be),
					  iip_sock_ip4_str(peer_ip4_be, peer_ip, sizeof(peer_ip)),
					  ntohs(peer_port_be));
		sock->connected = false;
		sock->closed = true;
		if (sock->closing) {
			iip_sock_unqueue_ready(sock);
			iip_sock_rxq_free(sock);
			free(sock);
		} else {
			iip_sock_queue_ready(sock);
		}
	} else {
		SPDK_NOTICELOG("iip tcp closed without sock handle=%p local=%s:%u peer=%s:%u\n",
			       handle,
			       iip_sock_ip4_str(local_ip4_be, local_ip, sizeof(local_ip)),
			       ntohs(local_port_be),
			       iip_sock_ip4_str(peer_ip4_be, peer_ip, sizeof(peer_ip)),
			       ntohs(peer_port_be));
	}
}

static void
iip_ops_udp_payload(void *mem, void *m, void *opaque)
{
	(void)mem;
	(void)m;
	(void)opaque;
}

static struct rte_mbuf *
iip_sock_mbuf_from_iovs(struct spdk_iip_group_impl *group, const struct iovec *iov, int iovcnt,
			size_t offset, size_t max_len, size_t *total_len)
{
	struct rte_mbuf *m;
	uint8_t *dst;
	size_t scan_offset = offset;
	size_t len = 0;
	int i;

	for (i = 0; i < iovcnt; i++) {
		size_t iov_len = iov[i].iov_len;

		if (scan_offset >= iov_len) {
			scan_offset -= iov_len;
			continue;
		}

		len += spdk_min(iov_len - scan_offset, max_len - len);
		scan_offset = 0;
		if (len == max_len) {
			break;
		}
	}

	if (len == 0 || len > UINT16_MAX) {
		errno = EMSGSIZE;
		return NULL;
	}

	m = iip_ops_pkt_alloc(group);
	if (m == NULL) {
		errno = ENOBUFS;
		return NULL;
	}
	if (len > rte_pktmbuf_tailroom(m)) {
		SPDK_NOTICELOG("iip send chunk too large len=%zu tailroom=%u\n",
			       len, rte_pktmbuf_tailroom(m));
		rte_pktmbuf_free(m);
		errno = EMSGSIZE;
		return NULL;
	}

	dst = rte_pktmbuf_mtod(m, uint8_t *);
	for (i = 0; i < iovcnt; i++) {
		size_t iov_len = iov[i].iov_len;
		size_t copy_len;

		if (offset >= iov_len) {
			offset -= iov_len;
			continue;
		}

		copy_len = spdk_min(iov_len - offset, len - *total_len);
		memcpy(dst, (uint8_t *)iov[i].iov_base + offset, copy_len);
		dst += copy_len;
		*total_len += copy_len;
		offset = 0;
		if (*total_len == len) {
			break;
		}
	}

	iip_ops_pkt_set_len(m, len, group);

	return m;
}

static int
iip_sock_send_iovs(struct spdk_iip_sock *sock, struct iovec *iov, int iovcnt,
		   size_t offset, size_t max_len, size_t *total_len)
{
	struct rte_mbuf *m;

	*total_len = 0;
	if (sock->owner_group == NULL || sock->tcp_handle == NULL || !sock->connected) {
		SPDK_NOTICELOG("iip send ENOTCONN sock=%p type=%d owner=%p base_group=%p handle=%p connected=%d closed=%d iovcnt=%d\n",
			       sock, sock->type, sock->owner_group, sock->base.group_impl, sock->tcp_handle,
			       sock->connected, sock->closed, iovcnt);
		errno = ENOTCONN;
		return -1;
	}

	m = iip_sock_mbuf_from_iovs(sock->owner_group, iov, iovcnt, offset, max_len, total_len);
	if (m == NULL) {
		return -1;
	}

	if (iip_tcp_send(sock->owner_group->workspace, sock->tcp_handle, m, 0x08U, sock->owner_group) != 0) {
		iip_ops_pkt_free(m, sock->owner_group);
		errno = EIO;
		return -1;
	}

	return 0;
}

static int
iip_sock_flush_queued_reqs(struct spdk_iip_sock *sock)
{
	struct spdk_sock_request *req, *tmp;
	struct iovec *iovs;
	size_t total_len, req_len;
	int bytes = 0;

	TAILQ_FOREACH_SAFE(req, &sock->base.queued_reqs, internal.link, tmp) {
		iovs = SPDK_SOCK_REQUEST_IOV(req, 0);
			IIP_SOCK_TRACELOG("iip flush req sock=%p req=%p iovcnt=%d owner=%p base_group=%p handle=%p connected=%d closed=%d\n",
					  sock, req, req->iovcnt, sock->owner_group, sock->base.group_impl,
					  sock->tcp_handle, sock->connected, sock->closed);
		req_len = 0;
		for (int i = 0; i < req->iovcnt; i++) {
			req_len += iovs[i].iov_len;
		}

		while (req->internal.offset < req_len) {
			if (iip_sock_send_iovs(sock, iovs, req->iovcnt, req->internal.offset,
					       IIP_SOCK_MAX_SEND_CHUNK, &total_len) != 0) {
				int err = errno;

				if (bytes > 0) {
					return bytes;
				}
				spdk_sock_request_pend(&sock->base, req);
				(void)spdk_sock_request_put(&sock->base, req, -err);
				errno = err;
				return -1;
			}
			req->internal.offset += total_len;
			bytes += total_len;
		}

		spdk_sock_request_pend(&sock->base, req);
		if (spdk_sock_request_put(&sock->base, req, 0) < 0) {
			break;
		}
	}

	return bytes;
}

static int
iip_sock_getaddr(struct spdk_sock *_sock, char *saddr, int slen, uint16_t *sport,
		 char *caddr, int clen, uint16_t *cport)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);

	if (saddr != NULL && slen > 0) {
		inet_ntop(AF_INET, &sock->local_ip_be, saddr, slen);
	}
	if (sport != NULL) {
		*sport = ntohs(sock->local_port_be);
	}
	if (caddr != NULL && clen > 0) {
		inet_ntop(AF_INET, &sock->peer_ip_be, caddr, clen);
	}
	if (cport != NULL) {
		*cport = ntohs(sock->peer_port_be);
	}

	return 0;
}

static struct spdk_sock *
iip_sock_connect(const char *ip, int port, struct spdk_sock_opts *opts)
{
	(void)ip;
	(void)port;
	(void)opts;
	errno = ENOTSUP;
	return NULL;
}

static struct spdk_sock *
iip_sock_listen(const char *ip, int port, struct spdk_sock_opts *opts)
{
	struct spdk_iip_sock *sock;
	uint32_t ip_be = 0;
	int rc;

	(void)opts;

	if (port <= 0 || port > UINT16_MAX) {
		errno = EINVAL;
		return NULL;
	}

	if (ip != NULL && ip[0] != '\0' && strcmp(ip, "0.0.0.0") != 0) {
		if (inet_pton(AF_INET, ip, &ip_be) != 1) {
			errno = EINVAL;
			return NULL;
		}
	}

	sock = calloc(1, sizeof(*sock));
	if (sock == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	sock->type = SPDK_IIP_SOCK_LISTEN;
	sock->local_ip_be = ip_be;
	sock->local_port_be = htons((uint16_t)port);
	TAILQ_INIT(&sock->rxq);
	TAILQ_INIT(&sock->pending_accepts);

	pthread_mutex_lock(&g_iip.lock);
	iip_sock_global_lists_init();
	if (g_iip.local_ip_be == 0) {
		g_iip.local_ip_be = ip_be;
	}
	rc = iip_sock_global_port_init();
	if (rc == 0) {
		memcpy(sock->local_mac, g_iip.local_mac, sizeof(sock->local_mac));
		TAILQ_INSERT_TAIL(&g_iip.listeners, sock, link);
	}
	pthread_mutex_unlock(&g_iip.lock);

	if (rc != 0) {
		free(sock);
		errno = -rc;
		return NULL;
	}

	return &sock->base;
}

static struct spdk_sock *
iip_sock_accept(struct spdk_sock *_sock)
{
	struct spdk_iip_sock *listener = __iip_sock(_sock);
	struct spdk_iip_sock *sock;

	if (listener->type != SPDK_IIP_SOCK_LISTEN) {
		errno = EINVAL;
		return NULL;
	}

	iip_sock_poll_idle_groups_for_accept();

	pthread_mutex_lock(&g_iip.lock);
	sock = TAILQ_FIRST(&listener->pending_accepts);
	if (sock != NULL) {
		TAILQ_REMOVE(&listener->pending_accepts, sock, pending_link);
	}
	pthread_mutex_unlock(&g_iip.lock);

	if (sock == NULL) {
		errno = EAGAIN;
		return NULL;
	}

	IIP_SOCK_TRACELOG("iip accept pop listener=%p sock=%p owner=%p handle=%p connected=%d closed=%d rxq=%zu\n",
			  listener, sock, sock->owner_group, sock->tcp_handle, sock->connected,
			  sock->closed, sock->rxq_bytes);
	return &sock->base;
}

static int
iip_sock_close(struct spdk_sock *_sock)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);
	struct spdk_iip_sock *child;

	IIP_SOCK_TRACELOG("iip close sock=%p type=%d owner=%p base_group=%p handle=%p connected=%d closed=%d rxq=%zu\n",
			  sock, sock->type, sock->owner_group, sock->base.group_impl, sock->tcp_handle,
			  sock->connected, sock->closed, sock->rxq_bytes);

	if (sock->type == SPDK_IIP_SOCK_LISTEN) {
		pthread_mutex_lock(&g_iip.lock);
		TAILQ_REMOVE(&g_iip.listeners, sock, link);
		while ((child = TAILQ_FIRST(&sock->pending_accepts)) != NULL) {
			TAILQ_REMOVE(&sock->pending_accepts, child, pending_link);
			iip_sock_unqueue_ready(child);
			iip_sock_rxq_free(child);
			free(child);
		}
		pthread_mutex_unlock(&g_iip.lock);
		free(sock);
		return 0;
	}

	iip_sock_unqueue_ready(sock);
	if (sock->connected && sock->owner_group != NULL && sock->tcp_handle != NULL) {
		sock->closing = true;
		sock->connected = false;
		iip_tcp_close(sock->owner_group->workspace, sock->tcp_handle, sock->owner_group);
		iip_ops_l2_flush(sock->owner_group);
		return 0;
	}

	iip_sock_rxq_free(sock);
	free(sock);
	return 0;
}

static ssize_t
iip_sock_readv(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);
	struct spdk_iip_rx_seg *seg;
	size_t copied = 0;
	int i;

	if (sock->type != SPDK_IIP_SOCK_STREAM) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < iovcnt; i++) {
		uint8_t *dst = iov[i].iov_base;
		size_t avail = iov[i].iov_len;

		while (avail > 0 && (seg = TAILQ_FIRST(&sock->rxq)) != NULL) {
			size_t n = spdk_min(avail, seg->len - seg->off);

			memcpy(dst, seg->buf + seg->off, n);
			dst += n;
			avail -= n;
			copied += n;
			seg->off += n;
			sock->rxq_bytes -= n;

			if (seg->off == seg->len) {
				TAILQ_REMOVE(&sock->rxq, seg, link);
				free(seg->buf);
				free(seg);
			}
		}
	}

	if (copied != 0) {
		return copied;
	}

	if (sock->closed || !sock->connected) {
		return 0;
	}

	errno = EAGAIN;
	return -1;
}

static ssize_t
iip_sock_recv(struct spdk_sock *sock, void *buf, size_t len)
{
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = len,
	};

	return iip_sock_readv(sock, &iov, 1);
}

static ssize_t
iip_sock_writev(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);
	size_t total_len = 0;
	size_t sent, offset = 0, req_len = 0;
	int i;

	for (i = 0; i < iovcnt; i++) {
		req_len += iov[i].iov_len;
	}

	while (offset < req_len) {
		if (iip_sock_send_iovs(sock, iov, iovcnt, offset,
				       IIP_SOCK_MAX_SEND_CHUNK, &sent) != 0) {
			return total_len == 0 ? -1 : (ssize_t)total_len;
		}
		offset += sent;
		total_len += sent;
	}

	return total_len;
}

static void
iip_sock_writev_async(struct spdk_sock *_sock, struct spdk_sock_request *req)
{
	if (req->iovcnt <= 0) {
		req->cb_fn(req->cb_arg, -EINVAL);
		return;
	}

	spdk_sock_request_queue(_sock, req);
}

static int
iip_sock_recv_next(struct spdk_sock *sock, void **buf, void **ctx)
{
	(void)sock;
	(void)buf;
	(void)ctx;
	errno = ENOTSUP;
	return -1;
}

static int
iip_sock_flush(struct spdk_sock *_sock)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);
	int bytes;

	bytes = iip_sock_flush_queued_reqs(sock);
	if (bytes < 0) {
		return -1;
	}

	if (sock->owner_group != NULL) {
		iip_ops_l2_flush(sock->owner_group);
	}

	return bytes;
}

static int
iip_sock_set_recvlowat(struct spdk_sock *_sock, int nbytes)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);

	sock->recvlowat = nbytes;
	return 0;
}

static int
iip_sock_set_recvbuf(struct spdk_sock *sock, int sz)
{
	(void)sock;
	(void)sz;
	return 0;
}

static int
iip_sock_set_sendbuf(struct spdk_sock *sock, int sz)
{
	(void)sock;
	(void)sz;
	return 0;
}

static bool
iip_sock_is_ipv6(struct spdk_sock *sock)
{
	(void)sock;
	return false;
}

static bool
iip_sock_is_ipv4(struct spdk_sock *sock)
{
	(void)sock;
	return true;
}

static bool
iip_sock_is_connected(struct spdk_sock *_sock)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);

	return sock->type == SPDK_IIP_SOCK_STREAM && sock->connected && !sock->closed;
}

static struct spdk_sock_group_impl *
iip_sock_group_impl_get_optimal(struct spdk_sock *_sock, struct spdk_sock_group_impl *hint)
{
	struct spdk_iip_sock *sock = __iip_sock(_sock);

	if (sock->owner_group != NULL) {
		return &sock->owner_group->base;
	}

	return hint;
}

static struct spdk_sock_group_impl *
iip_sock_group_impl_create(void)
{
	struct spdk_iip_group_impl *group;
	uint16_t queueid;
	int rc;

	group = calloc(1, sizeof(*group));
	if (group == NULL) {
		return NULL;
	}

	TAILQ_INIT(&group->ready_socks);

	pthread_mutex_lock(&g_iip.lock);
	iip_sock_global_lists_init();
	queueid = 0;
	if (!TAILQ_EMPTY(&g_iip.groups)) {
		struct spdk_iip_group_impl *last = TAILQ_LAST(&g_iip.groups, iip_group_tailq);

		queueid = last->queueid + 1;
	}
	if (g_iip.port_initialized && queueid >= g_iip.num_queues) {
		pthread_mutex_unlock(&g_iip.lock);
		free(group);
		return NULL;
	}
	group->queueid = queueid;
	group->portid = g_iip.portid;
	TAILQ_INSERT_TAIL(&g_iip.groups, group, link);
	pthread_mutex_unlock(&g_iip.lock);

	rc = iip_sock_alloc_stack_objs(group);
	if (rc != 0) {
		pthread_mutex_lock(&g_iip.lock);
		TAILQ_REMOVE(&g_iip.groups, group, link);
		pthread_mutex_unlock(&g_iip.lock);
		free(group);
		return NULL;
	}

	(void)iip_sock_group_refresh_config(group);
	return &group->base;
}

static int
iip_sock_group_impl_add_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	struct spdk_iip_group_impl *group = __iip_group(_group);
	struct spdk_iip_sock *sock = __iip_sock(_sock);
	struct spdk_iip_group_impl *prev_owner = sock->owner_group;

	if (sock->owner_group != NULL && sock->owner_group != group) {
		errno = EINVAL;
		return -1;
	}

	sock->owner_group = group;
	group->active_sock_count++;
		IIP_SOCK_TRACELOG("iip group add sock=%p group=%p queue=%u prev_owner=%p handle=%p connected=%d closed=%d rxq=%zu active=%u\n",
				  sock, group, group->queueid, prev_owner, sock->tcp_handle,
				  sock->connected, sock->closed, sock->rxq_bytes, group->active_sock_count);
	if (sock->rxq_bytes != 0 || sock->closed) {
		/*
		 * spdk_sock_group_add_sock() sets base.group_impl after this callback
		 * returns. Use owner_group here so data received before accept is not
		 * left queued with no readiness notification.
		 */
		iip_sock_queue_ready(sock);
	}

	return 0;
}

static int
iip_sock_group_impl_remove_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	struct spdk_iip_group_impl *group = __iip_group(_group);
	struct spdk_iip_sock *sock = __iip_sock(_sock);

	iip_sock_unqueue_ready(sock);
	if (group->active_sock_count > 0) {
		group->active_sock_count--;
	}

	return 0;
}

static int
iip_sock_group_impl_poll(struct spdk_sock_group_impl *_group, int max_events,
			 struct spdk_sock **socks)
{
	struct spdk_iip_group_impl *group = __iip_group(_group);
	struct spdk_iip_sock *sock;
	struct spdk_sock *_sock, *_sock_tmp;
	int count = 0;

	(void)iip_sock_group_refresh_config(group);
	(void)iip_sock_group_poll_rx(group);

	TAILQ_FOREACH_SAFE(_sock, &_group->socks, link, _sock_tmp) {
		if (iip_sock_flush_queued_reqs(__iip_sock(_sock)) < 0) {
			spdk_sock_abort_requests(_sock);
		}
	}

	while (count < max_events && (sock = TAILQ_FIRST(&group->ready_socks)) != NULL) {
		TAILQ_REMOVE(&group->ready_socks, sock, ready_link);
		sock->ready_queued = false;
		if (spdk_unlikely(sock->base.cb_fn == NULL)) {
			continue;
		}
		socks[count++] = &sock->base;
	}

	iip_ops_l2_flush(group);
	return count;
}

static int
iip_sock_group_impl_close(struct spdk_sock_group_impl *_group)
{
	struct spdk_iip_group_impl *group = __iip_group(_group);

	pthread_mutex_lock(&g_iip.lock);
	TAILQ_REMOVE(&g_iip.groups, group, link);
	pthread_mutex_unlock(&g_iip.lock);

	iip_ops_l2_flush(group);
	free(group);
	return 0;
}

static struct spdk_net_impl g_iip_net_impl = {
	.name = "iip",
	.getaddr = iip_sock_getaddr,
	.connect = iip_sock_connect,
	.listen = iip_sock_listen,
	.accept = iip_sock_accept,
	.close = iip_sock_close,
	.recv = iip_sock_recv,
	.readv = iip_sock_readv,
	.writev = iip_sock_writev,
	.recv_next = iip_sock_recv_next,
	.writev_async = iip_sock_writev_async,
	.flush = iip_sock_flush,
	.set_recvlowat = iip_sock_set_recvlowat,
	.set_recvbuf = iip_sock_set_recvbuf,
	.set_sendbuf = iip_sock_set_sendbuf,
	.is_ipv6 = iip_sock_is_ipv6,
	.is_ipv4 = iip_sock_is_ipv4,
	.is_connected = iip_sock_is_connected,
	.group_impl_get_optimal = iip_sock_group_impl_get_optimal,
	.group_impl_create = iip_sock_group_impl_create,
	.group_impl_add_sock = iip_sock_group_impl_add_sock,
	.group_impl_remove_sock = iip_sock_group_impl_remove_sock,
	.group_impl_poll = iip_sock_group_impl_poll,
	.group_impl_close = iip_sock_group_impl_close,
	.get_opts = iip_sock_impl_get_opts,
	.set_opts = iip_sock_impl_set_opts,
};

SPDK_NET_IMPL_REGISTER(iip, &g_iip_net_impl, DEFAULT_SOCK_PRIORITY + 2);
SPDK_LOG_REGISTER_COMPONENT(sock_iip)
