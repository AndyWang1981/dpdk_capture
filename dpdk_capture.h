/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019, AndyWang
 * All rights reserved.
 */

#ifndef _DPDK_CAPTURE_H_
#define _DPDK_CAPTURE_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

/* MACROS */
#define NB_MBUF 8192
#define MEMPOOL_CACHE_SIZE 256
#define	MBUF_DATA_SIZE	RTE_MBUF_DEFAULT_BUF_SIZE
#define RX_RING_SIZE 512
#define TX_RING_SIZE 512
#define BURST_SIZE 32
#define RTE_ETH_PCAP_SNAPSHOT_LEN 65535
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

static void print_mac_addr(uint16_t port_id);
static void print_stats(void);
static void open_pcap_file(const char *fname);
static void dump_pcap_file(const u_char *pkt, int len, time_t tv_sec, suseconds_t tv_usec);
static void handle_signal(int sig_num);
static inline int create_port_mp_ring_vdev(uint8_t port);
int lcore_main(void *arg);

#endif /* _DPDK_CAPTURE_H_ */
