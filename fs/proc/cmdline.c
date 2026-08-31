// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>

/* Gọi biến lưu trữ chuỗi cmdline hệ thống */
extern char *saved_command_line;

static int cmdline_proc_show(struct seq_file *m, void *v)
{
 char *copied_cmdline;
 char *p;

 /* Cấp phát vùng đệm tạm thời để xử lý chuỗi an toàn */
 copied_cmdline = kstrdup(saved_command_line, GFP_KERNEL);
 if (!copied_cmdline) {
  seq_printf(m, "%s\n", saved_command_line);
  return 0;
 }

 /* 
  * 1. Định vị và "vô hiệu hóa" các cờ bảo mật gốc bằng cách đổi tên.
  * Thay vì dịch chuyển byte nguy hiểm, ta chỉ cần đổi chữ 'androidboot' thành 'androidfake'.
  * Điều này làm Android Init bỏ qua giá trị cũ hoàn toàn mà không làm thay đổi cấu trúc/độ dài chuỗi.
  */
 p = strstr(copied_cmdline, "androidboot.verifiedbootstate");
 if (p) memcpy(p, "androidfake", 11);

 p = strstr(copied_cmdline, "androidboot.flash.locked");
 if (p) memcpy(p, "androidfake", 11);

 p = strstr(copied_cmdline, "androidboot.vbmeta.device_state");
 if (p) memcpy(p, "androidfake", 11);

 p = strstr(copied_cmdline, "androidboot.veritymode");
 if (p) memcpy(p, "androidfake", 11);

 /* 
  * 2. In chuỗi đã vô hiệu hóa cờ cũ, đồng thời chèn các cờ giả lập an toàn nhất vào cuối chuỗi.
  * Do cờ gốc đã biến mất, Android Init sẽ ưu tiên nhận các cờ xanh/khóa này một cách hợp lệ.
  */
 seq_printf(m, "%s androidboot.verifiedbootstate=green androidboot.flash.locked=1 androidboot.vbmeta.device_state=locked androidboot.veritymode=enforcing\n",
     copied_cmdline);

 /* Giải phóng vùng nhớ tạm */
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
 /* Sử dụng phân quyền đọc toàn cục 0444 giúp các tiến trình vendor Redmi đọc file bình thường */
 proc_create("cmdline", 0444, NULL, &cmdline_proc_fops);
 return 0;
}
fs_initcall(proc_cmdline_init);
