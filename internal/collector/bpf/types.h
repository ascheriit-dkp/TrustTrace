/* Minimal CO-RE views: field offsets are relocated against the running BTF. */
#ifndef TRUSTTRACE_TYPES_H
#define TRUSTTRACE_TYPES_H
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;
#define SEC(s) __attribute__((section(s), used))
#define INLINE static __attribute__((always_inline)) inline
#define CORE __attribute__((preserve_access_index))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define NULL ((void *)0)

struct qstr { u32 hash; u32 len; const unsigned char *name; } CORE;
struct dentry { struct dentry *d_parent; struct qstr d_name; } CORE;
struct vfsmount { struct dentry *mnt_root; } CORE;
struct mount { struct mount *mnt_parent; struct dentry *mnt_mountpoint; struct vfsmount mnt; } CORE;
struct path { struct vfsmount *mnt; struct dentry *dentry; } CORE;
struct super_block { u32 s_dev; } CORE;
struct inode { unsigned short i_mode; unsigned long i_ino; struct super_block *i_sb; } CORE;
struct file { struct path f_path; unsigned int f_flags; unsigned int f_mode; struct inode *f_inode; void *private_data; } CORE;
struct sock { unsigned short sk_protocol; } CORE;
struct socket { struct sock *sk; } CORE;
struct fdtable { unsigned int max_fds; struct file **fd; } CORE;
struct files_struct { struct fdtable *fdt; } CORE;
struct fs_struct { struct path root; struct path pwd; } CORE;
struct mm_struct { struct file *exe_file; } CORE;
struct thread_info { unsigned long flags; unsigned int status; } CORE;
struct task_struct { struct thread_info thread_info; int pid; int tgid; int exit_code; struct task_struct *real_parent; struct files_struct *files; struct fs_struct *fs; struct mm_struct *mm; } CORE;
struct linux_binprm { const char *filename; } CORE;

static void *(*map_lookup)(void *, const void *) = (void *)1;
static long (*map_update)(void *, const void *, const void *, u64) = (void *)2;
static long (*map_delete)(void *, const void *) = (void *)3;
static u64 (*ktime_ns)(void) = (void *)5;
static u64 (*pid_tgid)(void) = (void *)14;
static u64 (*uid_gid)(void) = (void *)15;
static void *(*current_task)(void) = (void *)35;
static long (*read_user)(void *, u32, const void *) = (void *)112;
static long (*read_kernel)(void *, u32, const void *) = (void *)113;
static long (*read_user_str)(void *, u32, const void *) = (void *)114;
static long (*read_kernel_str)(void *, u32, const void *) = (void *)115;
static long (*ring_output)(void *, void *, u64, u64) = (void *)130;
#define READ(dst, src) read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

enum { FORK=1, EXEC, EXIT, OPEN, WRITE, RENAME, DELETE, CONNECT, READ_FILE, UNSUPPORTED, LOAD, CREATE };
enum { PATH_LOSS=1, ARGV_LOSS=2, MEMORY_LOSS=4, THREAD=8, CREATED=16, REGULAR=32, SECOND_PATH_LOSS=64 };
enum { LOST_RING, LOST_MAP, LOST_CORRELATION, LOST_READ, LOST_PATH, LOST_ARGV, LOST_UNSUPPORTED, LOST_ABI, COUNTERS };
struct event {
    u64 time_ns, id, parent_id;
    s64 result;
    u32 pid, tid, ppid, uid, kind, flags;
    u32 aux, reserved;
    char path[256], path2[256];
    char argv[8][64];
    u8 address[16];
    u16 port, family;
    u32 protocol;
    u64 inode, device;
};
struct identity { u64 id, parent_id; u32 active, reserved; };
struct sys_enter { u64 common; s64 nr; u64 args[6]; };
struct sys_exit { u64 common; s64 nr; s64 ret; };
struct raw_args { u64 args[3]; };
#endif
