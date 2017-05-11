#define PROTOCOL_TCP 6
#define PROTOCOL_UDP 17
#define PROTOCOL_SMTP 25
#define PROTOCOL_HTTPS 443

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");				// Set the license
MODULE_AUTHOR("Eryk Szlachetka, Pamela Sabio"); // Set the Authors
MODULE_DESCRIPTION("Desc goes here");		// Set the description

/* Firewall policy struct */
struct mf_rule_desp {
	unsigned char in_out;
    	char *src_ip, *src_netmask, *src_port, *dest_ip, *dest_netmask, *dest_port;
	unsigned char proto;
	unsigned char action;
};

/* Firewall policy struct */

struct mf_rule {
	unsigned char in_out;       // 0 = Neither IN nor OUT, 1 = IN, 2 = OUT
	unsigned int src_ip;       
	unsigned int src_netmask;   
	unsigned int src_port;
	unsigned int dest_ip;

	unsigned int dest_netmask;
	unsigned int dest_port;
	unsigned char proto;        // 0 =  all, 1 = TCP, 2 = UDP
	unsigned char action;       // 0 = BLOCK, 1 = UNBLOCK
	struct list_head list;
};

static struct nf_hook_ops nfho, nfho_out;       // Struct holding set of hook function options
static unsigned char *ip = "\xC0\xA8\x00\x01"; // Ip in network byte order (192.168.0.1);
static char *interface = "lo";                 // Loop-back interface which will be blocked
unsigned char *telnet_port = "x00\x17";	       // The telnet port
struct udphdr *udp_header, *udp_header_out;
struct sk_buff *sk_buffer_in, *sk_buffer_out;
struct iphdr *ip_header, *ip_header_out;
struct tcphdr *tcp_header, *tcp_header_out;
//struct httphdr *http_header_in, *http_header_out;
//struct smpthdr *smtp_header_in, *smtp_header_out;

// Hook function for incoming packets.
unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	/*
	// Check if we are dealing with loop-back interface is so then drop it.
  	if(strcmp(state->in->name,interface) == 0){
		return NF_DROP;
  	}
	sk_buffer_in = skb;

	if(!(sk_buffer_in)) { return NF_ACCEPT; } // Validate socket_buff
	ip_header = (struct iphdr *)skb_network_header(sk_buffer_in); // Assign the ip_header
	if(!(ip_header)){return NF_ACCEPT;} // Validate IP Packet
	if(ip_header->saddr == *(unsigned int *)ip){return NF_DROP;} // Compare IP  

	if (ip_header->protocol == PROTOCOL_UDP){
		printk(KERN_INFO "UDP Packet\n");
		udp_header = (struct udphdr *)(skb_transport_header(skb) + 20);
		//udp_header = (struct udphdr *)(sk_buffer->data + (ip_header->ihl *4));
		printk(KERN_INFO "Source: %u\nDest: %u\n",udp_header->source,udp_header->dest);
		if((udp_header->dest) == *(unsigned short*)telnet_port){ return NF_DROP;}
		return NF_ACCEPT;
	}else if (ip_header->protocol == PROTOCOL_TCP) // Check if it is TCP protocol
	{
		printk(KERN_INFO "TCP Packet\n");
		tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); //Note: +20 is only for incoming packets
		printk(KERN_INFO "Source: %u\nDest: %u\n", tcp_header->source,tcp_header->dest);
		/*if(tcp_header->dest == PROTOCOL_SMTP){
			// SMTP
			printk(KERN_INFO "SMTP end-3"); 
		}else if(tcp_header->dest == PROTOCOL_HTTPS){
			// HTTP
			printk(KERN_INFO "Returning accept end-3");
			return NF_ACCEPT;
		} HERE 
		printk(KERN_INFO "Returning accept end-2");
		return NF_ACCEPT;
	}else{
		printk(KERN_INFO "Returning drop end-1");
  		return NF_DROP;
	}

	printk(KERN_INFO "Returning accept end");
	*/
	return NF_ACCEPT;

}

// Hook for outgoing packets.
unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
 // TODO Hook function for outgoing packets
	/*if(strcmp(state->in->name, interface) == 0){
		return NF_DROP;
	}

	sk_buffer_out = skb;

	if(!(sk_buffer_out)) { return NF_ACCEPT; } // Validate socket_buff
        ip_header_out = (struct iphdr *)skb_network_header(sk_buffer_out); // Assign$
        if(!(ip_header_out)){return NF_ACCEPT;} // Validate IP Packet
        if(ip_header_out->saddr == *(unsigned int *)ip){return NF_DROP;} // Compare$

        if (ip_header_out->protocol == PROTOCOL_UDP){
                printk(KERN_INFO "UDP Packet Out\n");
                udp_header_out = (struct udphdr *)(skb_transport_header(skb) + 20);
                //udp_header = (struct udphdr *)(sk_buffer->data + (ip_header->$
                printk(KERN_INFO "Source: %u\nDest: %u\n",udp_header_out->source,udp_header_out->dest);
                if((udp_header_out->dest) == *(unsigned short*)telnet_port){ return NF_DROP;}
                return NF_ACCEPT;
        }else if (ip_header_out->protocol == PROTOCOL_TCP) // Check if it is TCP pr$
        {
                printk(KERN_INFO "TCP Packet Out\n");
                tcp_header_out = (struct tcphdr *)(skb_transport_header(skb)+20);
                printk(KERN_INFO "Source: %u\nDest: %u\n", tcp_header_out->source,tcp_header_out->dest);
		printk(KERN_INFO "Returning accept end-2");
                return NF_ACCEPT;
        }else{
                printk(KERN_INFO "Returning drop end-1");
                return NF_DROP;
        }

        printk(KERN_INFO "Returning accept end");
        */
	return NF_ACCEPT;
	
}

//Called when module loaded using 'insmod'
int init_module()
{
	nfho.hook = hook_func_in;           //function to call when conditions below met
	nfho.hooknum = NF_INET_PRE_ROUTING; //called right after packet recieved, first hook in Netfilter
	nfho.pf = PF_INET;                  //IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;    //set to highest priority over all other hook functions

	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_POST_ROUTING;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;

	// Register hooks
	nf_register_hook(&nfho);
	nf_register_hook(&nfho_out);
  return 0;                           //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  nf_unregister_hook(&nfho);         //cleanup – unregister hook
}
