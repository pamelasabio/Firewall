#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
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
struct udphdr *udp_header;
struct sk_buff *sk_buffer;
struct iphdr *ip_header;

// Hook function that is assigned to nfho.hook
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	//struct udphdr *udp_header;	// Struct for UDP header
	struct tcphdr *tcp_header; 	// Struct for TCP header
	//struct iphdr *ip_header;	// Struct for IP header  (ip_header->saddr || ip_header->daddr)
	struct httphdr *http_header;	// Struct for HTTP header
	struct smtphdr *smtp_header;	// Struct for SMTP header

	// Check if we are dealing with loop-back interface is so then drop it.
  	if(strcmp(state->in->name,interface) == 0){
		return NF_DROP;
  	}
	sk_buffer = skb;

	if(!(sk_buffer)) { return NF_ACCEPT; } // Validate socket_buff
	ip_header = (struct iphdr *)skb_network_header(sk_buffer); // Assign the ip_header
	if(!(ip_header)){return NF_ACCEPT;} // Validate IP Packet
	if(ip_header->saddr == *(unsigned int *)ip){return NF_DROP;} // Compare IP  

	if (ip_header->protocol == PROTOCOL_UDP){
		printk(KERN_INFO "UDP Packet\n");
		//udp_header = (struct udphdr *)(skb_transport_header(skb) + 20);
		//printk(KERN_INFO "SOURCE PORT %u\n",udp_header->source);
		// or
		udp_header = (struct udphdr *)(sk_buffer->data + (ip_header->ihl *4));
		//printk(KERN_INFO "SOURCE 2 PORT %u\n",udp_header->source);
		if((udp_header->dest) == *(unsigned short*)telnet_port){ return NF_DROP;}
	}else if (ip_header->protocol == PROTOCOL_TCP) // Check if it is TCP protocol
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
