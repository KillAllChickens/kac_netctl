#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>

#define PROC_NAME "kac_net"
#define PROC_BUF_SZ 16

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vance Perry <vance@killallchickens.org>");
MODULE_DESCRIPTION("Simple netfilter toggle via /proc/kac_net");

static atomic_t block_all = ATOMIC_INIT(0);
static struct nf_hook_ops nfho;

/* netfilter hook: drop all IPv4 packets when block_all is set */
static unsigned int kac_nf_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	if (atomic_read(&block_all)) {
		pr_info("kac_netctl: dropping packet (hooknum=%d)\n", state->hook);
		return NF_DROP;
	}
	return NF_ACCEPT;
}

/* proc read: show status */
static ssize_t kac_proc_read(struct file* file, char __user* buf, size_t count, loff_t* ppos) {
	char out[PROC_BUF_SZ];
	int len = snprintf(out, sizeof(out), "%d\n", atomic_read(&block_all));
	return simple_read_from_buffer(buf, count, ppos, out, len);
}

/* proc write: write "1" to enable blocking, "0" to disable */
static ssize_t kac_proc_write(struct file* file, const char __user* buf, size_t count, loff_t* ppos) {
	char kbuf[PROC_BUF_SZ];
	unsigned long notused;

	if (count >= PROC_BUF_SZ)
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (kstrtoul(kbuf, 0, &notused) == 0) {
		/* Parsed a number */
		if (kbuf[0] == '0') {
			atomic_set(&block_all, 0);
			pr_info("kac_netctl: network blocking disabled\n");
		} else {
			atomic_set(&block_all, 1);
			pr_info("kac_netctl: network blocking enabled\n");
		}
	} else {
		/* fallback parse text */
		if (kbuf[0] == '0') {
			atomic_set(&block_all, 0);
			pr_info("kac_netctl: network blocking disabled\n");
		} else {
			atomic_set(&block_all, 1);
			pr_info("kac_netctl: network blocking enabled\n");
		}
	}

	return count;
}

static const struct proc_ops kac_proc_ops = {
    .proc_read = kac_proc_read,
    .proc_write = kac_proc_write,
};


static int __init kac_init(void) {
	int ret;

	/* create /proc/kac_net */
	if (!proc_create(PROC_NAME, 0600, NULL, &kac_proc_ops)) {
		pr_err("kac_netctl: failed to create /proc/%s\n", PROC_NAME);
		return -ENOMEM;
	}

	/* register netfilter hook for IPv4 PRE_ROUTING (covers incoming) */
	nfho.hook = kac_nf_hook;
	nfho.pf = NFPROTO_IPV4;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = NF_IP_PRI_FIRST;

	ret = nf_register_net_hook(&init_net, &nfho);
	if (ret) {
		pr_err("kac_netctl: nf_register_net_hook failed: %d\n", ret);
		remove_proc_entry(PROC_NAME, NULL);
		return ret;
	}

	pr_info("kac_netctl loaded. Control: /proc/%s (write 1 to block, 0 to allow)\n", PROC_NAME);
	return 0;
}

static void __exit kac_exit(void) {
	nf_unregister_net_hook(&init_net, &nfho);
	remove_proc_entry(PROC_NAME, NULL);
	pr_info("kac_netctl unloaded\n");
}

module_init(kac_init);
module_exit(kac_exit);
