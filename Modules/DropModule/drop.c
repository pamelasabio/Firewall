#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PAMELA SABIO, ERYK SZLACHETKA");
MODULE_DESCRIPTION("A kernel module to drop packets");

static struct nf_hook_ops netfilter_ops_in; // NF_IP_PRE_ROUTING 
static struct nf_hook_ops netfilter_ops_out; // NF_IP_POST_ROUTING 

// Function prototype in <linux/netfilter> 
unsigned int main_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return NF_DROP; //Drop ALL Packets
}
int init_module()
{
        netfilter_ops_in.hook                   =       hook_func;
        netfilter_ops_in.pf                     =       PF_INET;
        netfilter_ops_in.hooknum                =       NF_INET_PRE_ROUTING;
        netfilter_ops_in.priority               =       NF_IP_PRI_FIRST;
        netfilter_ops_out.hook                  =       hook_func;
        netfilter_ops_out.pf                    =       PF_INET;
        netfilter_ops_out.hooknum               =       NF_INET_POST_ROUTING;
        netfilter_ops_out.priority              =       NF_IP_PRI_FIRST;
        nf_register_hook(&netfilter_ops_in); // register NF_IP_PRE_ROUTING hook */
        nf_register_hook(&netfilter_ops_out); // register NF_IP_POST_ROUTING hook */
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops_in); //unregister NF_IP_PRE_ROUTING hook
	nf_unregister_hook(&netfilter_ops_out); //unregister NF_IP_POST_ROUTING hook
}
