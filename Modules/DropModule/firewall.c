#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PAMELA SABIO, ERYK SZLACHETKA");
MODULE_DESCRIPTION("Netfilter Firewall Module");

static struct nf_hook_ops netfilter_ops;
static unsigned char *ip_address = "\xC0\xA8\x00\x01";
static char *interface = "lo";
unsigned char *port = "\x00\x17";
struct sk_buff *sock_buff;
struct udphdr *udp_header;
struct iphdr *ip_header;

unsigned int main_hook(void *priv,
                  struct sk_buff *skb,
                  const struct nf_hook_state *state)
{
  if(strcmp(state->in->name,interface) == 0){ return NF_DROP; }
  sock_buff = skb;
  if(!sock_buff){ return NF_ACCEPT; }
  if(!(ip_header)){ return NF_ACCEPT; }
  if(ip_header->saddr == *(unsigned int*)ip_address){ return NF_DROP; }

if(ip_header->protocol != 17){ return NF_ACCEPT; }
udp_header = (struct udphdr *)(sock_buff->data + (ip_header->ihl *4));
if((udp_header->dest) == *(unsigned short*)port){ return NF_DROP; }
return NF_ACCEPT;
}
int init_module()
{
        netfilter_ops.hook              =       main_hook;
        netfilter_ops.pf                =       PF_INET;
        netfilter_ops.hooknum           =       NF_INET_PRE_ROUTING;
        netfilter_ops.priority          =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops);
	printk("HELLO WORLD");
	return 0;
}

void cleanup_module() { nf_unregister_hook(&netfilter_ops); }
