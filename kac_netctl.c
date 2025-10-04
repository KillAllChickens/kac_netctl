#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vance Perry <vance@killallchickens.org>");
MODULE_DESCRIPTION("KACOS networking toggle via sysfs");

static atomic_t block_all = ATOMIC_INIT(0);
static struct nf_hook_ops nfho_ipv4_pre;
static struct nf_hook_ops nfho_ipv4_out;
static struct nf_hook_ops nfho_ipv6_pre;
static struct nf_hook_ops nfho_ipv6_out;

/* netfilter hook: drop all IPv4 packets when block_all is set */
static unsigned int kac_nf_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
	if (atomic_read(&block_all)) {
		// pr_info("kac_netctl: dropping packet (hooknum=%d)\n", state->hook);
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static ssize_t block_all_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf) {
	return sysfs_emit(buf, "%d\n", atomic_read(&block_all));
}

static ssize_t block_all_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t count) {
	int val;
	int ret = kstrtoint(buf, 0, &val);
	if (ret)
		return ret;

	if (val == 0) {
		atomic_set(&block_all, 0);
		pr_info("kac_netctl: network blocking disabled\n");
	} else {
		atomic_set(&block_all, 1);
		pr_info("kac_netctl: network blocking enabled\n");
	}

	return count;
}

static struct kobj_attribute block_all_attribute = __ATTR(block_all, 0660, block_all_show, block_all_store);

static struct attribute* attrs[] = {
    &block_all_attribute.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = attrs,
};

// The kobject for our sysfs directory.
static struct kobject* kac_kobj;

static int __init kac_init(void) {
	int ret;

	kac_kobj = kobject_create_and_add("kac_net", kernel_kobj);
	if (!kac_kobj) {
		pr_err("kac_netctl: failed to create kobject\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(kac_kobj, &attr_group);
	if (ret) {
		pr_err("kac_netctl: failed to create sysfs group\n");
		kobject_put(kac_kobj); // Cleanup
		return ret;
	}

	/* register netfilter hook for IPv4 PRE_ROUTING (covers incoming) */
	nfho_ipv4_pre.hook = kac_nf_hook;
	nfho_ipv4_pre.pf = NFPROTO_IPV4;
	nfho_ipv4_pre.hooknum = NF_INET_PRE_ROUTING;
	nfho_ipv4_pre.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_ipv4_pre);

	nfho_ipv4_out.hook = kac_nf_hook;
	nfho_ipv4_out.pf = NFPROTO_IPV4;
	nfho_ipv4_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_ipv4_out.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_ipv4_out);

	nfho_ipv6_pre.hook = kac_nf_hook;
	nfho_ipv6_pre.pf = NFPROTO_IPV6;
	nfho_ipv6_pre.hooknum = NF_INET_PRE_ROUTING;
	nfho_ipv6_pre.priority = NF_IP6_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_ipv6_pre);

	nfho_ipv6_out.hook = kac_nf_hook;
	nfho_ipv6_out.pf = NFPROTO_IPV6;
	nfho_ipv6_out.hooknum = NF_INET_LOCAL_OUT;
	nfho_ipv6_out.priority = NF_IP6_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_ipv6_out);

	// ret = nf_register_net_hook(&init_net, &nfho);
	// if (ret) {
	// 	pr_err("kac_netctl: nf_register_net_hook failed: %d\n", ret);,.
	// 	remove_proc_entry(PROC_NAME, NULL);
	// 	return ret;
	// }

    pr_info("kac_netctl loaded. Control: /sys/kernel/kac_net/block_all\n");
	return 0;
}

static void __exit kac_exit(void) {
	nf_unregister_net_hook(&init_net, &nfho_ipv4_pre);
	nf_unregister_net_hook(&init_net, &nfho_ipv4_out);
	nf_unregister_net_hook(&init_net, &nfho_ipv6_pre);
	nf_unregister_net_hook(&init_net, &nfho_ipv6_out);

	kobject_put(kac_kobj);

	pr_info("kac_netctl unloaded\n");
}

module_init(kac_init);
module_exit(kac_exit);
