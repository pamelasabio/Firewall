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

static struct mf_rule policy_list;
static struct nf_hook_ops nfho_in, nfho_out;   // Struct holding set of hook function options
static unsigned char *ip = "\xC0\xA8\x00\x01"; // Ip in network byte order (192.168.0.1);
static char *interface = "lo";                 // Loop-back interface which will be blocked
unsigned char *telnet_port = "x00\x17";	       // The telnet port
struct udphdr *udp_header, *udp_header_out;
struct sk_buff *sk_buffer_in, *sk_buffer_out;
struct iphdr *ip_header, *ip_header_out;
struct tcphdr *tcp_header, *tcp_header_out;
//struct httphdr *http_header_in, *http_header_out;
//struct smpthdr *smtp_header_in, *smtp_header_out;


unsigned int port_str_to_int(char *port_str) {
	unsigned int port = 0;
	int i = 0;

	if (port_str==NULL) {
		return 0;
	}

	while (port_str[i]!=' ') {
		port = port*10 + (port_str[i]-'0');
		++i;
	}

	return port;
}

unsigned int ip_str_to_hl(char *ip_str) {

	/* Convert the STRING to BYTE ARRAY first, e.g.: from "122.111.195.3" to [122][111][195][3]*/
	unsigned char ip_array[4];
	int i = 0;
	unsigned int ip = 0;

	if (ip_str==NULL) {
		return 0; 
	}

	memset(ip_array, 0, 4);

	while (ip_str[i]!='.') {
		ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!='.') {
		ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!='.') {
		ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
	}

	++i;

	while (ip_str[i]!=' ') {
		ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
	}

	/* Convert from BYTE ARRAY to HOST LONG INT format */
	ip = (ip_array[0] << 24);
	ip = (ip | (ip_array[1] << 16));
	ip = (ip | (ip_array[2] << 8));
	ip = (ip | ip_array[3]);
	return ip;

}


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
	if(strcmp(state->in->name, interface) == 0){
		return NF_DROP;
	}
	
	if(!(sk_buffer_out)) { return NF_ACCEPT; } // Validate socket_buff
        ip_header_out = (struct iphdr *)skb_network_header(skb); // Assign$
        if(!(ip_header_out)){return NF_ACCEPT;} // Validate IP Packet
        if(ip_header_out->saddr == *(unsigned int *)ip){return NF_DROP;} // Compare$


	// Local variables for ip addresses, ports and data.
	unsigned int destination_ip = (unsigned int) ip_header_out -> daddr;
	unsigned int source_ip = (unsigned int) ip_header_out -> saddr;
	unsigned int destination_port = source_port = 0;
	unsigned int *user_data; 

	printk(KERN_INFO "Outgoing packet.");

	// Check if we are dealing with UDP PACKET
        if (ip_header_out->protocol == PROTOCOL_UDP){
                printk(KERN_INFO "UDP Packet Out\n");
                udp_header_out = (struct udphdr *)(skb_transport_header(skb) + 20);
		source_port = (unsigned int)ntohs(udp_header_out->source);
		destination_port = (unsigned int)ntohs(udp_header_out ->dest);
    		// DROP THE TELNET CONNECTIONS
                if((udp_header_out->dest) == *(unsigned short*)telnet_port){ return NF_DROP;}
        }else if (ip_header_out->protocol == PROTOCOL_TCP) // Check if we are dealing with TCP PACKET 
        {
                printk(KERN_INFO "TCP Packet Out\n");
                tcp_header_out = (struct tcphdr *)(skb_transport_header(skb)+20);
              	source_port = (unsigned int)ntohs(tcp_header_out->source);
		destination_port = (unsigned int)ntohs(tcp_header_out ->dest);

		// Check if we are dealing with port 80
		if(src_port == 80){
			printk(KERN_INFO "\n\nPORT 80!\n\n");
		}else{
			printk(KERN_INFO "\n\nNOT PORT 80: S: %u | D: %u \n\n", src_port, dest_port);
		}

		user_data = (unsigned char *) ((unsigned char*) tcp_header + (tcp_header->doff *4));
		if((user_data[0] = 'H') && (user_data[1] == 'T') && (user_data[2] == 'T') && (user_data[3] == 'P')){
			printk(KERN_INFO "\n\nHTTP DATA!\n\n");
		}else{
			printk(KERN_INFO "\n\nNOT HTTP! %c,%c,%c,%c \n\n", user_data[0], user_data[1], user_data[2], user_data[3]);
		}


        }else{
                printk(KERN_INFO "Returning drop end-1");
                return NF_DROP;
        }

        printk(KERN_INFO "Returning accept end");
        
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
