#include <linux/module.h>  // included for all kernel modules 
#include <linux/kernel.h>  // for kernel info
#include <linux/init.h>    // for _init and _exit


MODULE_LICENSE("GPL"); // Set the module licence
MODULE_AUTHOR("Eryk Szlachetka"); // Set the module Author
MODULE_DESCRIPTION("A simple program to illustrate how to develop kernel modules");

// Initialize function
static int __init initFunction(void)
{
	printk(KERN_INFO "Hello ! Initialized.\n"); // Print the message.
	return 0; // If non-zero means failure to load module.
}

// Exit function
static void __exit cleanFxn(void)
{
	printk(KERN_INFO "Exit fucntion, cleaning up!\n"); // Print the message.
}

module_init(initFunction);
module_exit(cleanFxn);
