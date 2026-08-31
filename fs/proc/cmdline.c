// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>

extern char *saved_command_line;

static int cmdline_proc_show(struct seq_file *m, void *v)
{
 char *copied_cmdline;
 char *p;

 copied_cmdline = kstrdup(saved_command_line, GFP_KERNEL);
 if (!copied_cmdline) {
  seq_printf(m, "%s\n", saved_command_line);
  return 0;
 }

 /* Vô hiệu hóa tiền tố androidboot.* */
 p = strstr(copied_cmdline, "androidboot.verifiedbootstate");
 if (p) memcpy(p, "androidfake", 11);

 p = strstr(copied_cmdline, "androidboot.flash.locked");
 if (p) memcpy(p, "androidfake", 11);

 p = strstr(copied_cmdline, "androidboot.vbmeta.device_state");
 if (p) memcpy(p, "androidfake", 11);

 p = strstr(copied_cmdline, "androidboot.veritymode");
 if (p) memcpy(p, "androidfake", 11);

 /* Vô hiệu hóa tiền tố vendor.boot.* (MediaTek) */
 p = strstr(copied_cmdline, "vendor.boot.verifiedbootstate");
 if (p) memcpy(p, "vendor.fake", 11);

 p = strstr(copied_cmdline, "vendor.boot.vbmeta.device_state");
 if (p) memcpy(p, "vendor.fake", 11);

 /* Nối các cờ spoof chuẩn vào cuối chuỗi */
 seq_printf(m, "%s androidboot.verifiedbootstate=green androidboot.flash.locked=1 androidboot.vbmeta.device_state=locked androidboot.veritymode=enforcing\n",
     copied_cmdline);

 kfree(copied_cmdline);
 return 0;
}

static int cmdline_proc_open(struct inode *inode, struct file *file)
{
 return single_open(file, cmdline_proc_show, NULL);
}

static const struct file_operations cmdline_proc_fops = {
 .open  = cmdline_proc_open,
 .read  = seq_read,
 .llseek  = seq_lseek,
 .release = single_release,
};

static int __init proc_cmdline_init(void)
{
 proc_create("cmdline", 0444, NULL, &cmdline_proc_fops);
 return 0;
}
fs_initcall(proc_cmdline_init);
