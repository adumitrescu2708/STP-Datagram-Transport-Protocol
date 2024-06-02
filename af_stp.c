// SPDX-License-Identifier: GPL-2.0+

/*
 * af_stp.c - SO2 Transport Protocol
 *
 * Author:
 *	Alexandra Dumitrescu <adumitrescu2708@stud.acs.upb.ro>,
 *	Andrei-Alexandru Podaru <andrei.podaru@stud.acs.upb.ro>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/net.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include "stp.h"

#define MAC_ADDRESS_LEN 6
#define proc_stp_file_permissions 0000
#define procfs_header "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts\n"

struct proc_dir_entry *proc_stp_file;

// new type of socket used by the protocol. First field is a `struct sock` so they can be
// safely cast to one another
struct stp_socket {
	struct sock sk;
	__be16 port;
	__be16 remote_port;
	int interface;
	__u8 remote_mac_addr[MAC_ADDRESS_LEN];
};

// list of bindings (`stp_socket` structs)
struct list_node {
	struct stp_socket *sock;
	struct list_head list;
};

LIST_HEAD(bindings_list);

// read-write lock to protect list accesses
DEFINE_RWLOCK(lock);

struct proto stp_proto = {
	.obj_size = sizeof(struct stp_socket),
	.owner = THIS_MODULE,
	.name = STP_PROTO_NAME,
};

struct info {
	unsigned int received_packets;
	unsigned int header_errors;
	unsigned int checksum_errors;
	unsigned int no_sock_errors;
	unsigned int no_buffer_errors;
	unsigned int sent_packets;
};

struct info *packets_stats;

// check if a (inteface, port) pair is already in use by iterating over the
// bindings list. Also takes into consideration special cases when interface index is 0
static int is_interface_port_busy(__be16 port, int interface)
{
	struct list_node *i;
	struct stp_socket *socket;

	read_lock(&lock);
	list_for_each_entry(i, &bindings_list, list) {
		socket = i->sock;
		if ((interface == 0 && socket->port == port)
			|| (socket->interface == 0 && socket->port == port)
			|| (socket->port == port && socket->interface == interface)) {
			read_unlock(&lock);
			return 1;
		}
	}

	read_unlock(&lock);
	return 0;
}

// adds an entry in the bindings list
static int add_binding(struct stp_socket *sock)
{
	struct list_node *binding_node = kcalloc(1, sizeof(*binding_node), GFP_KERNEL);

	if (!binding_node)
		return -ENOMEM;

	binding_node->sock = sock;

	write_lock(&lock);
	list_add(&binding_node->list, &bindings_list);
	write_unlock(&lock);

	return 0;
}

// returns the socket associated with a port given as parameter, by consulting
// the bindings list
static struct sock *get_sock_for_port(__be16 port)
{
	struct list_node *i;
	struct stp_socket *socket;

	read_lock(&lock);
	list_for_each_entry(i, &bindings_list, list) {
		socket = i->sock;
		if (socket->port == port) {
			read_unlock(&lock);
			return &socket->sk;
		}
	}

	read_unlock(&lock);
	return NULL;
}

// removes an entry from the bindings list
static int remove_binding(struct stp_socket *sock)
{
	struct list_head *i, *tmp;
	struct list_node *binding_node;

	write_lock(&lock);

	list_for_each_safe(i, tmp, &bindings_list) {
		binding_node = list_entry(i, struct list_node, list);
		if (binding_node->sock == sock) {
			list_del(i);
			kfree(binding_node);
			break;
		}
	}

	write_unlock(&lock);
	return 0;
}

// removes all entries from the bindings list
static void clear_bindings_list(void)
{
	struct list_head *i, *n;
	struct list_node *binding_node;

	list_for_each_safe(i, n, &bindings_list) {
		binding_node = list_entry(i, struct list_node, list);
		list_del(i);
		kfree(binding_node);
	}
}

static int stp_release(struct socket *sock)
{
	struct stp_socket *sock_stp = (struct stp_socket *) sock->sk;

	if (sock->state == SS_CONNECTING || sock->state == SS_CONNECTED)
		remove_binding(sock_stp);

	sock_put(&sock_stp->sk);

	return 0;
}

// associates a socket with a port and an interface
static int stp_bind(struct socket *sock, struct sockaddr *myaddr, int sockaddr_len)
{
	struct sockaddr_stp *myaddr_stp = (struct sockaddr_stp *) myaddr;
	struct stp_socket *sock_stp = (struct stp_socket *) sock->sk;
	int res;

	if (myaddr_stp->sas_family != AF_STP)
		return -EINVAL;

	// check if binding is available
	if (myaddr_stp->sas_port == 0 ||
		is_interface_port_busy(myaddr_stp->sas_port, myaddr_stp->sas_ifindex))
		return -EBUSY;

	sock_stp->interface = myaddr_stp->sas_ifindex;
	sock_stp->port = myaddr_stp->sas_port;

	// add a new binding to the list of bindings
	res = add_binding(sock_stp);
	if (!res)
		sock->state = SS_CONNECTING;

	return res;
}

// associates a socket with a remote port and remote MAC address
static int stp_connect(struct socket *sock, struct sockaddr *vaddr, int sockaddr_len, int flags)
{
	struct sockaddr_stp *vaddr_stp = (struct sockaddr_stp *) vaddr;
	struct stp_socket *sock_stp = (struct stp_socket *) sock->sk;

	sock_stp->remote_port = vaddr_stp->sas_port;
	memcpy(sock_stp->remote_mac_addr, vaddr_stp->sas_addr, MAC_ADDRESS_LEN);
	sock->state = SS_CONNECTED;

	return 0;
}

// computes the checksum of a packet, including its header, using the XOR function
static __u8 compute_checksum(struct sk_buff *sk_buffer)
{
	__u8 result = 0;
	unsigned char *iter = sk_buffer->head + sk_buffer->network_header;
	int steps = sk_buffer->data_len;

	while (steps) {
		result ^= *iter;
		iter++;
		steps--;
	}

	return result;
}

void add_stp_header_to_buff(struct sk_buff *sk_buffer, __be16 dest_port,
		__be16 src_port, int total_len, int proto, struct net_device *interface,
		int offset, struct msghdr *m)
{
	int len = total_len + sizeof(struct stp_hdr);
	struct stp_hdr *hdr = (struct stp_hdr *)skb_put(sk_buffer, len);

	hdr->csum = 0;
	hdr->dst = dest_port;
	hdr->src = src_port;
	hdr->len = len;
	hdr->flags = m->msg_flags;

	sk_buffer->data_len = len;
	sk_buffer->len += len;
	sk_buffer->protocol = proto;
	sk_buffer->dev = interface;

	skb_copy_datagram_from_iter(sk_buffer, offset + sizeof(*hdr), &m->msg_iter, total_len);

	hdr->csum = compute_checksum(sk_buffer);
}

// send a datagram on a socket
static int stp_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	struct stp_socket *sock_stp = (struct stp_socket *) sock->sk;
	DECLARE_SOCKADDR(struct sockaddr_stp *, addr, m->msg_name);
	struct net_device *interface = dev_get_by_index(sock_net(sock->sk), sock_stp->interface);
	struct sk_buff *sk_buffer;
	int hlen, dlen, tlen, err = 0, offset;
	__be16 remote_port;
	__u8 *remote_addr;

	if (sock->state == SS_UNCONNECTED ||
		!interface ||
		(!sock_stp->remote_port && m->msg_namelen < sizeof(struct sockaddr_stp)) ||
		sock->type != SOCK_DGRAM)
		return -EINVAL;

	// compute needed space for the header
	hlen = LL_RESERVED_SPACE(interface);
	tlen = interface->needed_tailroom;
	dlen = total_len + sizeof(struct stp_hdr);

	// create the send buffer
	sk_buffer = sock_alloc_send_pskb(
		&sock_stp->sk,
		hlen + tlen,
		dlen,
		m->msg_flags & MSG_DONTWAIT,
		&err,
		0
	);

	if (!sk_buffer)
		return -ENOMEM;

	skb_reserve(sk_buffer, hlen);
	skb_reset_network_header(sk_buffer);

	if (sock_stp->remote_port) {
		remote_port = sock_stp->remote_port;
		remote_addr = sock_stp->remote_mac_addr;
	} else {
		remote_port = addr->sas_port;
		remote_addr = addr->sas_addr;
	}

	offset = dev_hard_header(
		sk_buffer,
		interface,
		ETH_P_STP,
		remote_addr,
		interface->perm_addr,
		dlen
	);

	// add the specific header to the packet
	add_stp_header_to_buff(
		sk_buffer,
		remote_port,
		sock_stp->port,
		total_len,
		htons(ETH_P_STP),
		interface,
		offset,
		m
	);

	// send the packet down to the lower OSI levels
	err = dev_queue_xmit(sk_buffer);
	if (err)
		return err;

	dev_put(interface);

	// update stats
	packets_stats->sent_packets++;

	return total_len;
}

// receive a datagram on a socket
static int stp_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len, int flags)
{
	struct sk_buff *sk_buffer;
	__be16 initial_checksum, computed_checksum;
	int err;
	int data_len;
	int is_recv_blocking = flags & MSG_DONTWAIT;
	struct stp_hdr *hdr;

	if (sock->type != SOCK_DGRAM)
		return -EINVAL;

	// receive the datagram from the lower OSI levels in a `struct sk_buff` buffer
	sk_buffer = skb_recv_datagram(
		sock->sk,
		flags,
		is_recv_blocking,
		&err
	);

	if (!sk_buffer)
		return -EINVAL;

	// check if header is valid
	hdr = (struct stp_hdr *)skb_network_header(sk_buffer);
	if (sk_buffer->data_len < sizeof(struct stp_hdr) || !hdr->dst || !hdr->src) {
		packets_stats->header_errors++;
		return -EINVAL;
	}

	initial_checksum = hdr->csum;

	// recompute the checksum and see if it matches the original value
	hdr->csum = 0;
	computed_checksum = compute_checksum(sk_buffer);

	if (computed_checksum != initial_checksum) {
		packets_stats->checksum_errors++;
		return -EINVAL;
	}

	// determine the length of the data in the buffer (excluding the STP header)
	data_len = sk_buffer->data_len - sizeof(struct stp_hdr);
	if (data_len > total_len)
		data_len = total_len;

	err = skb_copy_datagram_iter(
		sk_buffer,
		sizeof(struct stp_hdr),
		&m->msg_iter,
		data_len
	);

	if (err)
		return err;

	// free the buffer
	consume_skb(sk_buffer);

	// update stats
	packets_stats->received_packets++;

	return total_len;
}

// operations associated with the protocol
static const struct proto_ops stp_ops = {
		.family = PF_STP,
		.owner = THIS_MODULE,
		.release = stp_release,
		.bind = stp_bind,
		.connect = stp_connect,
		.socketpair = sock_no_socketpair,
		.accept = sock_no_accept,
		.getname = sock_no_getname,
		.poll = datagram_poll,
		.ioctl = sock_no_ioctl,
		.listen = sock_no_listen,
		.shutdown = sock_no_shutdown,
		.sendmsg = stp_sendmsg,
		.recvmsg = stp_recvmsg,
		.mmap = sock_no_mmap,
		.sendpage = sock_no_sendpage,
};

int socket_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;

	// check if the correct protocol and type of sockets are used
	if (protocol != IPPROTO_IP)
		return -EINVAL;

	if (sock->type != SOCK_DGRAM && sock->type != SOCK_RAW &&
	    sock->type != SOCK_PACKET)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;

	// allocate memory for the socket
	sk = sk_alloc(net, AF_STP, GFP_KERNEL, &stp_proto, kern);
	if (!sk)
		return -ENOBUFS;

	// initialize socket fields
	sock_init_data(sock, sk);
	sock->ops = &stp_ops;
	sock->state = SS_FREE;
	sk->sk_family = AF_STP;
	sk->sk_protocol = protocol;

	return 0;
}

// the family of the new protocol
static struct net_proto_family stp_proto_family = {
	.family = AF_STP,
	.create = socket_create,
	.owner = THIS_MODULE,
};

// function that prints the packet stats (called when the file in the procfs is read)
static int stp_print(struct seq_file *m, void *v)
{
	seq_puts(m, procfs_header);

	seq_printf(
		m,
		"%u %u %u %u %u %u\n",
		packets_stats->received_packets,
		packets_stats->header_errors,
		packets_stats->checksum_errors,
		packets_stats->no_sock_errors,
		packets_stats->no_buffer_errors,
		packets_stats->sent_packets
	);

	return 0;
}


static int stp_file_open(struct inode *inode, struct file *file)
{
	return single_open(file, stp_print, NULL);
}

// function that handles a STP packet before it is associated with a socket.
// It searches the socket it belongs to and queues it there.
// It also checks for errors and updates the corresponding stats
int stp_recv(struct sk_buff *skb, struct net_device *dev,
				struct packet_type *pt,  struct net_device *orig_dev)
{
	struct stp_hdr *hdr;
	int result;
	struct sock *sk;

	// sanity checks
	if (!skb || !dev_has_header(dev))
		return -EINVAL;

	hdr = (struct stp_hdr *)skb_network_header(skb);

	if (dev_parse_header_protocol(skb) != htons(ETH_P_STP))
		return -EINVAL;

	// get the socket associated with the destination port found in the packet
	sk = get_sock_for_port(hdr->dst);
	if (!sk) {
		packets_stats->no_sock_errors++;
		return -EINVAL;
	}

	// queue the packet to the found socket
	result = sock_queue_rcv_skb(sk, skb);
	if (result) {
		packets_stats->no_buffer_errors++;
		return result;
	}

	return 0;
}

static const struct proc_ops r_pops = {
	.proc_open		= stp_file_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static struct packet_type stp_packet_type = {
	.type = htons(ETH_P_STP),
	.func = stp_recv,
};

/* init and exit functions for the module */

static int stp_init(void)
{
	int res;

	res = proto_register(&stp_proto, 1);
	if (res)
		return res;

	res = sock_register(&stp_proto_family);
	if (res) {
		proto_unregister(&stp_proto);
		return res;
	}

	dev_add_pack(&stp_packet_type);

	proc_stp_file = proc_create(
						STP_PROC_NET_FILENAME,
						proc_stp_file_permissions,
						init_net.proc_net,
						&r_pops
					);
	if (!proc_stp_file)
		goto proc_cleanup;

	packets_stats = kcalloc(1, sizeof(*packets_stats), GFP_ATOMIC);
	if (!packets_stats)
		goto proc_cleanup;

	goto succ;

proc_cleanup:
	proto_unregister(&stp_proto);
	sock_unregister(AF_STP);
	proc_remove(proc_stp_file);
	dev_remove_pack(&stp_packet_type);
	return -ENOMEM;

succ:
	return 0;
}

static void stp_exit(void)
{
	proto_unregister(&stp_proto);
	sock_unregister(AF_STP);
	kfree(packets_stats);
	proc_remove(proc_stp_file);
	dev_remove_pack(&stp_packet_type);
	clear_bindings_list();
}

module_init(stp_init);
module_exit(stp_exit);

MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR(
	"Alexandra Dumitrescu <adumitrescu2708@stud.acs.upb.ro>, Andrei-Alexandru Podaru <andrei.podaru@stud.acs.upb.ro>"
);
MODULE_LICENSE("GPL v2");
