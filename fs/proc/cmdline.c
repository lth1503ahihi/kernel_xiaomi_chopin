// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>

/* Hàm xóa tham số cũ truyền từ bootloader */
static void remove_param(char *buf, const char *key)
{
 char *pos = strstr(buf, key);
 if (!pos)
  return;

 while (*pos && *pos != ' ' && *pos != '\n') {
  *pos = ' ';
  pos++;
 }
}

static int cmdline_proc_show(struct seq_file *m, void *v)
{
 char *buf;

 buf = kstrdup(saved_command_line, GFP_KERNEL);
 if (!buf) {
  seq_printf(m, "%s\n", saved_command_line);
  return 0;
 }

 /* Xóa các cờ unlocked thực tế */
 remove_param(buf, "androidboot.verifiedbootstate=");
 remove_param(buf, "androidboot.flash.locked=");
 remove_param(buf, "androidboot.vbmeta.device_state=");

 /* Bơm các cờ locked/green giả lập vào chuỗi trả về cho Userspace */
 seq_printf(m, "%s androidboot.verifiedbootstate=green androidboot.flash.locked=1 androidboot.vbmeta.device_state=locked\n", buf);

 kfree(buf);
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
 proc_create("cmdline", 0, NULL, &cmdline_proc_fops);
 return 0;
}
fs_initcall(proc_cmdline_init);
