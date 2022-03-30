/*
A sample L4 load balancer
-------------------------
In this sample, the app serves as an L4 load balancer.
1. It listens to ARP requests and replies with it's own IP.
2. It listens to TCP packets, and depending on the port, forwards them to backend 1, backend 2, or drops them.
3. The app and both backends are all expected to be in the same broadcast domain.

To run:
- Machine 1 (app):
  - Create a VM on Hyper-V
  - Build DPDK (see https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html)
  - Add another interface (which is bound to an external virtual switch), so you can keep using existing interface for SSH
  - Write down the IPv4 the interface got from the DHCP, you'll use it for the env constants
  - Configure the driver and huge pages (see below)
- Machine 2 (backends)
  - Create a VM on Hyper-V
  - Add another 2 interfaces (bound to an external virtual switch), they will server as the 2 backends
    (we can just as well use 2 machines, but this is simpler and functionally similar)
  - Write down their IP and MAC addresses, you'll use it for the env constants
- Update env constants below
- Build and run this app on Machine 1
- Start multiple servers on machine 2, from separate terminals (the following commands will listen on all interfaces):
  - python3 -m http.server 8150
  - python3 -m http.server 8250
  - python3 -m http.server 8350
- Make requests to Machine 1, using the IP of the new interface
  (you'll see the requests reaching different servers, or timing out, depending on the port you used)

|--------------------
|Driver
|--------------------
|When using a Hyper-V VM, use the following driver: https://doc.dpdk.org/guides/nics/netvsc.html
|
|To install, run the following from a root shell:
|DEV_UUID=$(basename $(readlink /sys/class/net/eth1/device))
|NET_UUID="f8615163-df3e-46c5-913f-f2d2f965ed0e"
|modprobe uio_hv_generic
|echo $NET_UUID > /sys/bus/vmbus/drivers/uio_hv_generic/new_id
|echo $DEV_UUID > /sys/bus/vmbus/drivers/hv_netvsc/unbind
|echo $DEV_UUID > /sys/bus/vmbus/drivers/uio_hv_generic/bind
|
|To uninstall (and return to the regular driver):
|DEV_UUID=<see id in /sys/bus/vmbus/drivers/uio_hv_generic/>
|NET_UUID="f8615163-df3e-46c5-913f-f2d2f965ed0e"
|echo $DEV_UUID > /sys/bus/vmbus/drivers/uio_hv_generic/unbind
|echo $DEV_UUID > /sys/bus/vmbus/drivers/hv_netvsc/bind
|--------------------

|--------------------
|Huge pages
|--------------------
|run as root: echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
|--------------------
*/

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <map>
#include <tuple>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define IPv4_BYTES_FMT "%hu.%hu.%hu.%hu"
#define IPv4_BYTES(addr)                  \
	(uint8_t)(((addr) >> 24) & 0xFF),     \
		(uint8_t)(((addr) >> 16) & 0xFF), \
		(uint8_t)(((addr) >> 8) & 0xFF),  \
		(uint8_t)((addr)&0xFF)

// env constants
uint32_t                MY_DECLARED_IP              = RTE_IPV4(192, 168, 1, 10);
struct rte_ether_addr   BACKEND_MAC_1               = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint32_t                BACKEND_IP_1                = RTE_IPV4(192, 168, 1, 21);
int                     BACKEND_1_PORT_RANGE_START  = 8100;
int                     BACKEND_1_PORT_RANGE_END    = 8199;
struct rte_ether_addr   BACKEND_MAC_2               = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint32_t                BACKEND_IP_2                = RTE_IPV4(192, 168, 1, 22);
int                     BACKEND_2_PORT_RANGE_START  = 8200;
int                     BACKEND_2_PORT_RANGE_END    = 8299;


// initialize port (nic)
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool, char *driver_name, struct rte_ether_addr *addr)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0)
	{
		printf("port_init: Error during getting device (port %hu) info: %s\n",
			   port, strerror(-retval));
		return retval;
	}
	strncpy(driver_name, dev_info.driver_name, RTE_MP_MAX_NAME_LEN);
	driver_name[RTE_MP_MAX_NAME_LEN] = '\0';

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++)
	{
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
										rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++)
	{
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
										rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	retval = rte_eth_macaddr_get(port, addr);
	if (retval != 0)
		return retval;

	printf(
		"port_init: name: %s, driver name: %s, id: %hu, MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
		dev_info.device->name, dev_info.driver_name, port, RTE_ETHER_ADDR_BYTES(addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}

// send tcp packet, after correcting ipv4 and tcp checksums
void
send_tcp(uint16_t port, struct rte_mbuf* mbuf, struct rte_tcp_hdr *tcp_hdr, struct rte_ipv4_hdr *ipv4_hdr)
{
	ipv4_hdr->hdr_checksum = tcp_hdr->cksum = 0;
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
	rte_eth_tx_burst(port, 0, &mbuf, 1);
}

// main loop
static __rte_noreturn void
loop(
	int port,
	struct rte_ether_addr *my_mac,
	uint32_t my_ip,
	struct rte_ether_addr backend_mac_1,
	uint32_t backend_ip_1,
	struct rte_ether_addr backend_mac_2,
	uint32_t backend_ip_2)
{
	// map of <server ip, server dest port> -> <client ip, client mac>
	// when the server returns a packet, we use this to know what client to forward it to
	std::map<std::pair<int32_t, int16_t>, std::pair<int32_t, rte_ether_addr>> nat_map;
	for (;;)
	{
		// get packets
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

		// printf("loop: Got %hu packets\n", nb_rx);
		for (int i = 0; i < nb_rx; ++i)
		{
			bool free_packet = true;
			struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);

			// for arp or my IP, return my MAC
			if (rte_cpu_to_be_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP)
			{
				struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

				//printf(
				//	"loop: Got ARP request for: " IPv4_BYTES_FMT " from " IPv4_BYTES_FMT "\n",
				//	IPv4_BYTES(rte_cpu_to_be_32(arp_hdr->arp_data.arp_tip)),
				//	IPv4_BYTES(rte_cpu_to_be_32(arp_hdr->arp_data.arp_sip)));

				if (rte_cpu_to_be_32(arp_hdr->arp_data.arp_tip) == my_ip &&
					arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST))
				{
					printf("loop: arp for my IP, returning my MAC\n");
					arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
					/* Switch src and dst data and set bonding MAC */
					rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
					rte_ether_addr_copy(my_mac, &eth_hdr->src_addr);
					rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &arp_hdr->arp_data.arp_tha);
					arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
					rte_ether_addr_copy(my_mac, &arp_hdr->arp_data.arp_sha);
					arp_hdr->arp_data.arp_sip = rte_cpu_to_be_32(my_ip);
					rte_eth_tx_burst(port, 0, &bufs[i], 1);
					free_packet = false;
				}
			}
			// for IPv4, forward
			else if (rte_cpu_to_be_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4)
			{
				// get ipv4 header
				struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
				//printf(
				//	"loop: Got IPv4 from " IPv4_BYTES_FMT " to " IPv4_BYTES_FMT "\n",
				//	IPv4_BYTES(rte_cpu_to_be_32(ipv4_hdr->src_addr)),
				//	IPv4_BYTES(rte_cpu_to_be_32(ipv4_hdr->dst_addr)));
				//printf("loop: src mac: %02X:%02X:%02X:%02X:%02X:%02X\n", RTE_ETHER_ADDR_BYTES(&eth_hdr->src_addr));
				
				// only handle tcp
				if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
					struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(bufs[i], struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv4_hdr));

					int32_t dest_ip = rte_cpu_to_be_32(ipv4_hdr->dst_addr);
					int32_t src_ip = rte_cpu_to_be_32(ipv4_hdr->src_addr);
					int16_t dest_port = rte_cpu_to_be_16(tcp_hdr->dst_port);
					int16_t src_port = rte_cpu_to_be_16(tcp_hdr->src_port);
					
					// if packet is from backend, return to client
					if (src_ip == backend_ip_1 || src_ip == backend_ip_2) {
						// find who to return it to
						decltype(nat_map)::iterator it = nat_map.find(std::make_pair(src_ip, src_port));
						if (it == nat_map.end()) {
							printf("loop: error: entry not found");
						} else {
							printf("loop: got ipv4 tcp from backend, forwarding to " IPv4_BYTES_FMT "\n", IPv4_BYTES(it->second.first));
							rte_ether_addr_copy(&it->second.second, &eth_hdr->dst_addr);
							rte_ether_addr_copy(my_mac, &eth_hdr->src_addr);
							ipv4_hdr->dst_addr = rte_cpu_to_be_32(it->second.first);
							ipv4_hdr->src_addr = rte_cpu_to_be_32(my_ip);

							send_tcp(port, bufs[i], tcp_hdr, ipv4_hdr);
							free_packet = false;
						}
					} else { // new connection, forward to backend
						struct rte_ether_addr selected_backend_mac;
						uint32_t selected_backend_ip;
						uint selected_backend_number = 0;

						// forward to backend depending on port, or drop
						if (dest_port >= BACKEND_1_PORT_RANGE_START && dest_port <= BACKEND_1_PORT_RANGE_END) {
							selected_backend_ip = backend_ip_1;
							selected_backend_mac = backend_mac_1;
							selected_backend_number = 1;
						} else if (dest_port >= BACKEND_2_PORT_RANGE_START && dest_port <= BACKEND_2_PORT_RANGE_END) {
							selected_backend_ip = backend_ip_2;
							selected_backend_mac = backend_mac_2;
							selected_backend_number = 2;
						} else {
							printf("loop: port %hu blocked\n", dest_port);
						}

						if (selected_backend_number != 0) {
							// store nat entry
							nat_map[std::make_pair(selected_backend_ip, dest_port)] = std::make_pair(src_ip, eth_hdr->src_addr);

							// update src/dest and send
							rte_ether_addr_copy(&selected_backend_mac, &eth_hdr->dst_addr);
							rte_ether_addr_copy(my_mac, &eth_hdr->src_addr);
							ipv4_hdr->dst_addr = rte_cpu_to_be_32(selected_backend_ip);
							ipv4_hdr->src_addr = rte_cpu_to_be_32(my_ip);
							send_tcp(port, bufs[i], tcp_hdr, ipv4_hdr);
							free_packet = false;
						}
					}
				}
			}
			
			if (free_packet) {
				rte_pktmbuf_free(bufs[i]);
			}
		}
	}
}

// get the port with the net_netvsc driver, which is the driver for hyper-v interfaces
static int
get_my_port_id(struct rte_ether_addr *addr)
{
	printf("get_my_port_id: available interfaces: %hu\n", rte_eth_dev_count_avail());

	// allocate mbuf
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
															MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	uint16_t portid;
	char driver_name[RTE_MP_MAX_NAME_LEN + 1];
	RTE_ETH_FOREACH_DEV(portid)
	{
		if (port_init(portid, mbuf_pool, driver_name, addr) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %hu\n",
					 portid);
		if (strcmp("net_netvsc", driver_name) == 0)
		{
			printf("get_my_port_id: found net_netvsc interface %hu\n", portid);
			return portid;
		}
	}
	rte_exit(EXIT_FAILURE, "Cannot find net_netvsc interface\n");
}

int main(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	struct rte_ether_addr my_port_addr;
	int my_port_id;
	my_port_id = get_my_port_id(&my_port_addr);
	loop(my_port_id, &my_port_addr, MY_DECLARED_IP, BACKEND_MAC_1, BACKEND_IP_1, BACKEND_MAC_2, BACKEND_IP_2);

	return rte_eal_cleanup();
}
