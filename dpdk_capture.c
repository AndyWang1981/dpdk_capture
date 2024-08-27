/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019, AndyWang
 * All rights reserved.
 */

#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <inttypes.h>
#include <pcap.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_launch.h>
#include "dpdk_capture.h"


struct rte_eth_conf g_port_conf_default;
volatile uint8_t g_manual_quit;
int g_Running = 0;

pcap_dumper_t *g_pcap_dumper =NULL;
unsigned g_nCapPort = 0;

static void print_mac_addr(uint16_t port_id)
{
    struct rte_ether_addr addr;
    int ret;

	ret = rte_eth_macaddr_get(port_id, &addr);
	if (0 != ret)
		rte_exit(EXIT_FAILURE, "macaddr get failed\n");

	printf("MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n\n",
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);
}


static void print_stats(void)
{
	struct rte_eth_stats eth_stats;

    rte_eth_stats_get(g_nCapPort, &eth_stats);
    printf("\nPort %u stats:\n", g_nCapPort);
    printf(" - Pkts in:   %"PRIu64"\n", eth_stats.ipackets);
    printf(" - Pkts out:  %"PRIu64"\n", eth_stats.opackets);
    printf(" - Pkts imis: %"PRIu64"\n", eth_stats.imissed);
    printf(" - In Errs:   %"PRIu64"\n", eth_stats.ierrors);
    printf(" - Out Errs:  %"PRIu64"\n", eth_stats.oerrors);
    printf(" - Mbuf Errs: %"PRIu64"\n", eth_stats.rx_nombuf);
}

static void open_pcap_file(const char *fname)
{
	pcap_t *pcap;
	/*
	 * We need to create a dummy empty pcap_t to use it
	 * with pcap_dump_open(). We create big enough an Ethernet
	 * pcap holder.
	 */
	pcap = pcap_open_dead(DLT_EN10MB, RTE_ETH_PCAP_SNAPSHOT_LEN);
    g_pcap_dumper = pcap_dump_open(pcap, fname);
    if (NULL == g_pcap_dumper)
    {
        printf("Pcap dumper is NULL\n");
        return;
    }
}

static void dump_pcap_file(const u_char *pkt, int len, time_t tv_sec, suseconds_t tv_usec)
{
    struct pcap_pkthdr hdr;

    hdr.ts.tv_sec = tv_sec;
    hdr.ts.tv_usec = tv_usec;
    hdr.caplen = len;
    hdr.len = len; 

    pcap_dump((u_char*)g_pcap_dumper, &hdr, pkt); 
}

static void handle_signal(int sig_num)
{
	if (sig_num == SIGINT) 
    {
		printf("\n\nSignal %d received, preparing to exit...\n",sig_num);
        g_manual_quit = 1;
        print_stats();

        if (0 == g_Running)
        {
            exit(0);
        }
    }
}

static inline int create_port_mp_ring_vdev(uint8_t port)
{
    struct rte_mempool *mbuf_pool;
    int ret;
    uint16_t q;
    uint8_t nb_ports = rte_eth_dev_count_avail();
    unsigned socket = rte_socket_id();

    if (!rte_eth_dev_is_valid_port(port))
    {
        printf("Port is wrong\n");
        return -1;
    }

    /* Create mempool */
    mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
        NB_MBUF * nb_ports,
        MEMPOOL_CACHE_SIZE, 0, MBUF_DATA_SIZE,
        socket);

    if (NULL == mbuf_pool)
    {
        printf("Failed to create mbuf_pool\n");
        return -1;
    }

    g_port_conf_default.rxmode.max_rx_pkt_len = RTE_ETHER_MAX_LEN;
    struct rte_eth_conf port_conf = g_port_conf_default;

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port, &dev_info);
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
    {
        port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    
    const uint16_t nb_rx_queues = 1;
    const uint16_t nb_tx_queues = 1;

    /* Configure the Ethernet device*/
    ret = rte_eth_dev_configure(port, nb_rx_queues, nb_tx_queues, &port_conf);
    if (0 != ret)
    {
        printf("Failed to configure dev\n");
        return ret;
    }

    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);

    /* RX setup */
    for (q = 0; q < nb_rx_queues; q++) 
    {
        ret= rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port),NULL, mbuf_pool);
        if (ret < 0)
        {
            printf("Failed to rte_eth_rx_queue_setup\n");
            return ret;
        }
    }

    /* TX setup */
    for (q = 0; q < nb_tx_queues; q++) 
    {
        ret= rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
        if (ret < 0)
        {
            printf("Failed to rte_eth_tx_queue_setup\n");
            return ret;
        }
    }

    /* Start the Ethernet port */
    ret = rte_eth_dev_start(port);
    if (ret < 0)
    {
        printf("Failed to rte_eth_dev_start\n");
        return ret;
    }

    /* Enable RX in promiscuous mode for the Ethernet device */
    rte_eth_promiscuous_enable(port);

    return 0;
}

int lcore_main(void *arg)
{
    char file[64] = {0};
    time_t tNow = time(NULL);   
    struct tm now = *(localtime(&tNow));
    
    if (NULL == g_pcap_dumper)
    {
        snprintf(file, sizeof(file), "%04d%02d%02d_%02d%02d%02d.pcap",1900+now.tm_year, now.tm_mon, now.tm_mday,
                    now.tm_hour, now.tm_min, now.tm_sec);
        open_pcap_file(file);
    }

    unsigned int lcore_id = rte_lcore_id();
    RTE_LOG(INFO, APP, "%s() started on lcore %u\n", __func__, lcore_id);

    while (!g_manual_quit)
    {
        g_Running = 1;
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb_rx;
        uint16_t nb_tx;

        nb_rx = rte_eth_rx_burst(g_nCapPort, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        for (int i= 0; i < nb_rx; i++)
        {
            struct timeval tv;
            gettimeofday(&tv, NULL);

            char *pktbuf = rte_pktmbuf_mtod(bufs[i], char *);
            dump_pcap_file((const u_char*)pktbuf, bufs[i]->data_len, tv.tv_sec, tv.tv_usec);
        }
    }

    RTE_LOG(INFO, APP, "%s() exit on lcore %u\n", __func__, lcore_id);
    return 0;
}

int main(int argc, char *argv[])
{
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_panic("Cannot init EAL\n");

    argc -= ret;
    argv += ret;

    g_manual_quit = 0;
    signal(SIGINT, handle_signal);

    printf("\n\n");
    uint16_t  nb_ports = rte_eth_dev_count_avail();
	if (0 == nb_ports)
		rte_exit(EXIT_FAILURE, "No Ethernet ports\n");

    for (uint16_t i = 0; i < nb_ports; i++) 
    {
        char dev_name[RTE_DEV_NAME_MAX_LEN];
        rte_eth_dev_get_name_by_port(i, dev_name);
        printf("Port number %d: %s  ", i, dev_name);
        print_mac_addr(i);
    }

    printf("Please choose port number: \n");
    scanf("%d",&g_nCapPort);

    /* create mempool, ring and vdevs info */
    if (0 != create_port_mp_ring_vdev(g_nCapPort))
    {
        rte_exit(EXIT_FAILURE, "Failed to create port\n");
    }

    rte_eal_mp_remote_launch(lcore_main, NULL, SKIP_MASTER);
    rte_eal_mp_wait_lcore();

    exit(0);
}
