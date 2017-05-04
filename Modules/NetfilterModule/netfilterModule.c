#define PROTOCOL_PORT_TCP 6
#define PROTOCOL_PORT_UDP 17
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");				// Set the license
MODULE_AUTHOR("Eryk Szlachetka, Pamela Sabio"); // Set the Authors
MODULE_DESCRIPTION("Desc goes here");		// Set the description

static struct nf_hook_ops nfho;		       // Struct holding set of hook function options
static unsigned char *ip = "\xC0\xA8\x00\x01"; // Ip in network byte order (192.168.0.1);
static char *interface = "lo";                 // Loop-back interface which will be blocked
unsigned char *telnet_port = "x00\x17";	       // The telnet port

// Hook function that is assigned to nfho.hook
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct sk_buff *socket_buff;	// Socket kernel buffer
	struct udphdr *upd_header;	// Struct for UDP header
	struct tcphdr *tcp_header; 	// Struct for TCP header
	struct iphdr *ip_header;	// Struct for IP header  (ip_header->saddr || ip_header->daddr)
	struct httphdr *http_header;	// Struct for HTTP header
	struct smtphdr *smtp_header;	// Struct for SMTP header
	// TODO: Figure out a way to access net_device struct in this version of kernel
	// Check if we are dealing with loop-back interface is so then drop it.
  	//if(strcmp(in->name,interface) == 0){
	//	return NF_DROP;
  	//}
	// Assign *skb to socket_buff
	socket_buff = skb;
	//if(!(socket_buff)) { return NF_ACCEPT; } // Validate socket_buff
	//if(!(socket_buff->nh.iph)) { return NF_ACCEPT; }; // Validate IP packet
	//if(socket_buff->nh.ipg->saddr == *(unsigned int*)ip){return NF_DROP;} // Compare ip addresses
	
	// TODO COMPARE WITH UDP
	 
	*ip_header = (struct iphdr *)skb_network_header(skb); // Assign the ip_header
	if (ip_header->protocol == PROTOCOL_PORT_TCP) // Check if it is TCP protocol
	{
		printk(KERN_INFO "TCP Packet\n");
		tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); //Note: +20 is only for incoming packets
		printk(KERN_INFO "Source Port: %u\n", tcp_header->source);
 		printk(KERN_INFO "Dest Port: %u\n", tcp_header->dest);
	}
  
  return NF_ACCEPT;                                                                   //accept the packet
}

//Called when module loaded using 'insmod'
int init_module()
{
  nfho.hook = hook_func;              //function to call when conditions below met
  nfho.hooknum = NF_INET_PRE_ROUTING; //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                  //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;    //set to highest priority over all other hook functions
  nf_register_hook(&nfho);            //register hook

  return 0;                           //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);         //cleanup – unregister hook
}
