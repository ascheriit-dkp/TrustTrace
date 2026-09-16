// SPDX-License-Identifier: MIT
#include "types.h"

struct { __uint(type, 1); __uint(max_entries, 16384); __type(key, u32); __type(value, struct identity); } tracked SEC(".maps");
struct { __uint(type, 1); __uint(max_entries, 8192); __type(key, u32); __type(value, struct event); } pending SEC(".maps");
struct { __uint(type, 6); __uint(max_entries, COUNTERS); __type(key, u32); __type(value, u64); } counters SEC(".maps");
struct { __uint(type, 6); __uint(max_entries, 1); __type(key, u32); __type(value, struct event); } scratch SEC(".maps");
struct { __uint(type, 27); __uint(max_entries, 8 * 1024 * 1024); } events SEC(".maps");
struct { __uint(type, 2); __uint(max_entries, 1); __type(key,u32); __type(value,u64); } sequence SEC(".maps");
struct path_space { char data[512]; };
struct { __uint(type, 6); __uint(max_entries, 1); __type(key,u32); __type(value,struct path_space); } path_scratch SEC(".maps");

INLINE void count(u32 key) { u64 *v = map_lookup(&counters, &key); if (v) (*v)++; }
INLINE struct event *fresh(u32 kind, struct identity *identity) {
    u32 zero=0; struct event *e = map_lookup(&scratch, &zero);
    if (!e) return NULL;
    #pragma unroll
    for(int i=0;i<sizeof(*e)/8;i++) ((volatile u64 *)e)[i]=0;
    u64 ids=pid_tgid(); e->tid=(u32)ids; e->pid=ids>>32;
    e->time_ns=ktime_ns(); e->kind=kind; e->uid=(u32)uid_gid();
    e->id=identity->id; e->parent_id=identity->parent_id;
    struct task_struct *t=current_task(), *parent=NULL;
    READ(parent,t->real_parent); if(parent) READ(e->ppid,parent->tgid);
    return e;
}
INLINE void emit(struct event *e) {
    if (e->flags & (PATH_LOSS|SECOND_PATH_LOSS)) count(LOST_PATH);
    if (e->flags & ARGV_LOSS) count(LOST_ARGV);
    if (e->flags & MEMORY_LOSS) count(LOST_READ);
    if (ring_output(&events,e,sizeof(*e),0)) count(LOST_RING);
}

/* Bounded kernel path snapshot, including mount crossings. Fail closed: no
 * partial path is presented as absolute. Userspace does display normalization.
 * The task's fs root is the boundary, so paths are in its filesystem namespace. */
static __attribute__((noinline)) int build_path(struct path *path, char *out) {
    struct dentry *d=NULL,*root_d=NULL; struct vfsmount *mnt=NULL,*root_m=NULL;
    struct task_struct *t=current_task(); struct fs_struct *fs=NULL;
    READ(d,path->dentry); READ(mnt,path->mnt); READ(fs,t->fs);
    if (!fs || !d || !mnt) return -1;
    READ(root_d,fs->root.dentry); READ(root_m,fs->root.mnt);
    u32 off=255; out[255]=0;
    for (int i=0; i<32; i++) {
        if(d==root_d && mnt==root_m) {
            if(off==255) out[254]='/';
            return 0;
        }
        struct dentry *mr=NULL; READ(mr,mnt->mnt_root);
        if(d==mr) {
            struct mount *m=(void *)((char *)mnt-__builtin_preserve_field_info(((struct mount *)0)->mnt,0));
            struct mount *parent=NULL; READ(parent,m->mnt_parent);
            if(!parent || parent==m) return -1;
            READ(d,m->mnt_mountpoint);
            mnt=__builtin_preserve_access_index(&parent->mnt);
            continue;
        }
        u32 len=0; const unsigned char *name=NULL; struct dentry *parent=NULL;
        READ(len,d->d_name.len); READ(name,d->d_name.name); READ(parent,d->d_parent);
        if(!len || len>254 || len+1>off || !name || parent==d) return -1;
        u32 next=off-len;
        if(next==0 || next>254 || off>255) return -1;
        char saved=out[off & 255];
        if(read_kernel_str(out+(next & 255),len+1,name)<0) return -1;
        out[off & 255]=saved;
        off=(next-1)&255; out[off]='/'; d=parent;
    }
    return -1;
}
static __attribute__((noinline)) int path_string(struct path *path,char *out) {
    u32 zero=0;struct path_space *space=map_lookup(&path_scratch,&zero);
    if(!space) return -1;
    // A helper's dynamic offset and length are verified independently. Use a
    // 512-byte workspace for a <=256-byte path, then copy the bounded result.
    #pragma unroll
    for(int i=0;i<32;i++) ((volatile u64 *)space->data)[i]=0;
    int result=build_path(path,space->data);
    if(!result) __builtin_memcpy(out,space->data,256);
    return result;
}
INLINE struct file *get_file(u32 fd) {
    struct task_struct *t=current_task(); struct files_struct *files=NULL;
    struct fdtable *fdt=NULL; struct file **fds=NULL,*file=NULL; u32 max=0;
    READ(files,t->files); if(!files) return NULL;
    READ(fdt,files->fdt); if(!fdt) return NULL;
    READ(max,fdt->max_fds); READ(fds,fdt->fd);
    if(fd>=max || fd>1048576 || !fds) return NULL;
    read_kernel(&file,sizeof(file),&fds[fd]); return file;
}
INLINE void fd_path(struct event *e,u32 fd) {
    struct file *f=get_file(fd); struct inode *inode=NULL; u16 mode=0;
    if(!f) {e->flags|=PATH_LOSS;return;}
    READ(inode,f->f_inode); if(inode) READ(mode,inode->i_mode);
    if((mode & 0170000)==0100000) e->flags|=REGULAR;
    if(path_string(__builtin_preserve_access_index(&f->f_path),e->path)) e->flags|=PATH_LOSS;
}
INLINE void user_path(struct event *e,const char *p,int dirfd,char *out,u32 loss) {
    long n=read_user_str(out,256,p);
    if(n<=0) {e->flags|=MEMORY_LOSS|loss;return;}
    if(n==256) e->flags|=loss;
    // Relative paths retain their literal name; path2 is used only for rename.
    // Capture the base separately in argv, a union-like payload for file events.
    if(out[0]!='/') {
        struct task_struct *t=current_task(); struct fs_struct *fs=NULL;
        char *base=(char *)e->argv + (out==e->path2 ? 256 : 0);
        if(dirfd==-100) {
            READ(fs,t->fs);
            if(!fs || path_string(__builtin_preserve_access_index(&fs->pwd),base)) e->flags|=loss;
        } else {
            struct file *f=get_file((u32)dirfd);
            if(!f || path_string(__builtin_preserve_access_index(&f->f_path),base)) e->flags|=loss;
        }
    }
}

SEC("raw_tracepoint/sched_process_fork") int on_fork(struct raw_args *ctx) {
    struct task_struct *p=(void *)ctx->args[0], *c=(void *)ctx->args[1];
    u32 parent=0,child=0,tgid=0; READ(parent,p->pid);
    struct identity *v=map_lookup(&tracked,&parent); if(!v || !v->active) return 0;
    READ(child,c->pid); READ(tgid,c->tgid);
    u32 zero=0;u64 *seq=map_lookup(&sequence,&zero);if(!seq) {count(LOST_MAP);return 0;}
    struct identity next={.id=__sync_fetch_and_add(seq,1)+2,.parent_id=v->id,.active=1};
    if(map_update(&tracked,&child,&next,0)) count(LOST_MAP);
    struct event *e=fresh(FORK,&next); if(!e) return 0;
    e->tid=child; e->pid=tgid; READ(e->ppid,p->tgid);
    if(child!=tgid) e->flags|=THREAD;
    emit(e); return 0;
}

SEC("raw_tracepoint/sched_process_exec") int on_exec(struct raw_args *ctx) {
    u32 tid=(u32)pid_tgid(),old=(u32)ctx->args[1];
    struct identity *v=map_lookup(&tracked,&old); if(!v) return 0;
    struct identity identity=*v;
    struct event *saved=map_lookup(&pending,&old);
    struct event *e=fresh(EXEC,&identity); if(!e) return 0;
    if(saved) {__builtin_memcpy(e->argv,saved->argv,sizeof(e->argv)); e->reserved=saved->reserved; e->flags=saved->flags & (ARGV_LOSS|MEMORY_LOSS);}
    else { count(LOST_CORRELATION); e->flags|=ARGV_LOSS; }
    struct task_struct *t=current_task(); struct mm_struct *mm=NULL; struct file *f=NULL;
    READ(mm,t->mm); if(mm) READ(f,mm->exe_file);
    if(!f || path_string(__builtin_preserve_access_index(&f->f_path),e->path)) e->flags|=PATH_LOSS;
    if(f) {struct inode *inode=NULL;struct super_block *sb=NULL;u32 dev=0;
        READ(inode,f->f_inode);if(inode) {READ(e->inode,inode->i_ino);READ(sb,inode->i_sb);}
        if(sb) READ(dev,sb->s_dev);e->device=dev;}
    struct linux_binprm *b=(void *)ctx->args[2]; const char *filename=NULL;
    READ(filename,b->filename);
    long requested=read_kernel_str(e->path2,256,filename);
    if(requested<=0) e->flags|=MEMORY_LOSS|SECOND_PATH_LOSS;
    if(requested==256) e->flags|=SECOND_PATH_LOSS;
    identity.active=1;
    if(old!=tid) map_delete(&tracked,&old);
    if(map_update(&tracked,&tid,&identity,0)) count(LOST_MAP);
    map_delete(&pending,&old); emit(e); return 0;
}
SEC("raw_tracepoint/sched_process_exit") int on_exit(struct raw_args *ctx) {
    u32 tid=(u32)pid_tgid(); struct identity *v=map_lookup(&tracked,&tid);
    if(!v) return 0;
    struct event *e=fresh(EXIT,v);
    if(e) {struct task_struct *t=current_task(); int status=0; READ(status,t->exit_code);e->result=status;emit(e);}
    map_delete(&pending,&tid); map_delete(&tracked,&tid); return 0;
}

// Architecture syscall numbers are build-time constants, never host guesses.
#if defined(__TARGET_ARCH_x86)
#define NR_READ 0
#define NR_WRITE 1
#define NR_OPEN 2
#define NR_PREAD 17
#define NR_PWRITE 18
#define NR_PREADV 295
#define NR_PWRITEV 296
#define NR_PREADV2 327
#define NR_PWRITEV2 328
#define NR_READV 19
#define NR_WRITEV 20
#define NR_CONNECT 42
#define NR_EXEC 59
#define NR_RENAME 82
#define NR_CREAT 85
#define NR_MKDIR 83
#define NR_RMDIR 84
#define NR_LINK 86
#define NR_SYMLINK 88
#define NR_MKNOD 133
#define NR_MKDIRAT 258
#define NR_MKNODAT 259
#define NR_LINKAT 265
#define NR_SYMLINKAT 266
#define NR_UNLINK 87
#define NR_OPENAT 257
#define NR_UNLINKAT 263
#define NR_RENAMEAT 264
#define NR_RENAMEAT2 316
#define NR_EXECAT 322
#define NR_MMAP 9
#define NR_TRUNCATE 76
#define NR_FTRUNCATE 77
#define NR_SENDFILE 40
#define NR_COPY_FILE_RANGE 326
#define NR_SPLICE 275
#define NR_SENDTO 44
#define NR_SENDMSG 46
#elif defined(__TARGET_ARCH_arm64)
#define NR_READ 63
#define NR_WRITE 64
#define NR_OPEN -1
#define NR_PREAD 67
#define NR_PWRITE 68
#define NR_PREADV 69
#define NR_PWRITEV 70
#define NR_PREADV2 286
#define NR_PWRITEV2 287
#define NR_READV 65
#define NR_WRITEV 66
#define NR_CONNECT 203
#define NR_EXEC 221
#define NR_RENAME -1
#define NR_CREAT -1
#define NR_MKDIR -1
#define NR_RMDIR -1
#define NR_LINK -1
#define NR_SYMLINK -1
#define NR_MKNOD -1
#define NR_MKDIRAT 34
#define NR_MKNODAT 33
#define NR_LINKAT 37
#define NR_SYMLINKAT 36
#define NR_UNLINK -1
#define NR_OPENAT 56
#define NR_UNLINKAT 35
#define NR_RENAMEAT 38
#define NR_RENAMEAT2 276
#define NR_EXECAT 281
#define NR_MMAP 222
#define NR_TRUNCATE 45
#define NR_FTRUNCATE 46
#define NR_SENDFILE 71
#define NR_COPY_FILE_RANGE 285
#define NR_SPLICE 76
#define NR_SENDTO 206
#define NR_SENDMSG 211
#else
#error Unsupported architecture
#endif
#define NR_OPENAT2 437
#define NR_IO_URING_SETUP 425

INLINE int native_abi(s64 nr) {
    struct task_struct *t=current_task();unsigned long flags=0;
    if(READ(flags,t->thread_info.flags)) {count(LOST_READ);return 0;}
    #if defined(__TARGET_ARCH_x86)
    unsigned int status=0;
    if(__builtin_preserve_field_info(t->thread_info.status,2)) READ(status,t->thread_info.status);
    // TIF_ADDR32, TS_COMPAT and the x32 syscall bit respectively.
    if((flags & (1UL<<29)) || (status & 2) || (nr & 0x40000000)) return 0;
    #else
    if(flags & (1UL<<22)) return 0; // arm64 TIF_32BIT
    #endif
    return 1;
}

SEC("tracepoint/raw_syscalls/sys_enter") int on_enter(volatile struct sys_enter *ctx) {
    u32 tid=(u32)pid_tgid(); struct identity *v=map_lookup(&tracked,&tid);
    if(!v) return 0;
    s64 nr=ctx->nr; u32 kind=0;
    if(nr<0) return 0;
    if(!native_abi(nr)) {count(LOST_ABI);return 0;}
    if(nr==NR_EXEC||nr==NR_EXECAT) kind=EXEC;
    else if(nr==NR_OPEN||nr==NR_CREAT||nr==NR_OPENAT||nr==NR_OPENAT2) kind=OPEN;
    else if(nr==NR_WRITE||nr==NR_PWRITE||nr==NR_WRITEV||nr==NR_PWRITEV||nr==NR_PWRITEV2||nr==NR_FTRUNCATE||nr==NR_TRUNCATE) kind=WRITE;
    else if(nr==NR_READ||nr==NR_PREAD||nr==NR_READV||nr==NR_PREADV||nr==NR_PREADV2) kind=READ_FILE;
    else if(nr==NR_RENAME||nr==NR_RENAMEAT||nr==NR_RENAMEAT2) kind=RENAME;
    else if(nr==NR_UNLINK||nr==NR_UNLINKAT||nr==NR_RMDIR) kind=DELETE;
    else if(nr==NR_MKDIR||nr==NR_MKDIRAT||nr==NR_MKNOD||nr==NR_MKNODAT||nr==NR_LINK||nr==NR_LINKAT||nr==NR_SYMLINK||nr==NR_SYMLINKAT) kind=CREATE;
    else if(nr==NR_CONNECT) kind=CONNECT;
    else if(nr==NR_MMAP && (ctx->args[2]&4) && !(ctx->args[3]&0x20)) kind=LOAD;
    else if(nr==NR_IO_URING_SETUP||nr==NR_SENDFILE||nr==NR_COPY_FILE_RANGE||nr==NR_SPLICE||nr==NR_SENDMSG) kind=UNSUPPORTED;
    else if(nr==NR_SENDTO && ctx->args[4]) kind=UNSUPPORTED;
    else if(nr==NR_MMAP && (ctx->args[2]&2) && (ctx->args[3]&1)) kind=UNSUPPORTED;
    if(!kind) return 0;
    if(!v->active && kind!=EXEC) return 0;
    struct event *e=fresh(kind,v); if(!e) return 0;
    if(kind==EXEC) {
        // Both volatile loads use fixed context offsets. Selecting a context
        // pointer then dereferencing it is rejected by the tracepoint verifier.
        u64 exec_argv=ctx->args[1],execat_argv=ctx->args[2];
        const char **argv=(void *)(nr==NR_EXEC?exec_argv:execat_argv);
        for(int i=0;i<8;i++) {
            const char *s=NULL;
            if(read_user(&s,sizeof(s),argv+i)) {e->flags|=MEMORY_LOSS;break;}
            if(!s) break;
            e->reserved=i+1;
            long n=read_user_str(e->argv[i],64,s);
            if(n<=0) e->flags|=MEMORY_LOSS;
            if(n==64) e->flags|=ARGV_LOSS;
        }
        const char *extra=NULL;
        if(e->reserved==8 && read_user(&extra,sizeof(extra),argv+8)==0 && extra) e->flags|=ARGV_LOSS;
    } else if(kind==OPEN) {
        if(nr==NR_OPEN||nr==NR_CREAT) user_path(e,(void *)ctx->args[0],-100,e->path,PATH_LOSS);
        else user_path(e,(void *)ctx->args[1],(int)ctx->args[0],e->path,PATH_LOSS);
        if(nr==NR_OPEN) e->aux=ctx->args[1];
        else if(nr==NR_CREAT) e->aux=0101|01000;
        else if(nr==NR_OPENAT) e->aux=ctx->args[2];
        else {u64 flags=0;if(read_user(&flags,8,(void *)ctx->args[2])) e->flags|=MEMORY_LOSS;e->aux=flags;}
    } else if(kind==LOAD) {
        fd_path(e,(u32)ctx->args[4]);e->aux=ctx->args[2];e->reserved=ctx->args[3];
    } else if(kind==WRITE||kind==READ_FILE) {
        if(nr==NR_TRUNCATE) user_path(e,(void *)ctx->args[0],-100,e->path,PATH_LOSS);
        else fd_path(e,(u32)ctx->args[0]);
        if(nr==NR_FTRUNCATE||nr==NR_TRUNCATE) e->aux=1;
    } else if(kind==RENAME) {
        if(nr==NR_RENAME) {
            user_path(e,(void *)ctx->args[0],-100,e->path,PATH_LOSS);
            user_path(e,(void *)ctx->args[1],-100,e->path2,SECOND_PATH_LOSS);
        } else {
            user_path(e,(void *)ctx->args[1],(int)ctx->args[0],e->path,PATH_LOSS);
            user_path(e,(void *)ctx->args[3],(int)ctx->args[2],e->path2,SECOND_PATH_LOSS);
            if(nr==NR_RENAMEAT2) e->aux=ctx->args[4];
        }
    } else if(kind==DELETE) {
        if(nr==NR_UNLINK||nr==NR_RMDIR) user_path(e,(void *)ctx->args[0],-100,e->path,PATH_LOSS);
        else user_path(e,(void *)ctx->args[1],(int)ctx->args[0],e->path,PATH_LOSS);
    } else if(kind==CREATE) {
        if(nr==NR_MKDIR||nr==NR_MKDIRAT||nr==NR_MKNOD||nr==NR_MKNODAT) {
            e->aux=(nr==NR_MKDIR||nr==NR_MKDIRAT)?1:4;
            if(nr==NR_MKDIR||nr==NR_MKNOD) user_path(e,(void *)ctx->args[0],-100,e->path,PATH_LOSS);
            else user_path(e,(void *)ctx->args[1],(int)ctx->args[0],e->path,PATH_LOSS);
        } else if(nr==NR_LINK||nr==NR_LINKAT) {
            e->aux=2;
            if(nr==NR_LINK) {
                user_path(e,(void *)ctx->args[1],-100,e->path,PATH_LOSS);
                user_path(e,(void *)ctx->args[0],-100,e->path2,SECOND_PATH_LOSS);
            } else {
                user_path(e,(void *)ctx->args[3],(int)ctx->args[2],e->path,PATH_LOSS);
                char first=0;
                // AT_EMPTY_PATH names the source fd itself. Do not send the
                // empty string through ordinary relative-path capture first:
                // a failed string read would leave a stale loss flag behind.
                if((ctx->args[4]&0x1000) && !read_user(&first,1,(void *)ctx->args[1]) && first==0) {
                    struct file *f=get_file((u32)ctx->args[0]);
                    if(!f || path_string(__builtin_preserve_access_index(&f->f_path),e->path2)) e->flags|=SECOND_PATH_LOSS;
                } else user_path(e,(void *)ctx->args[1],(int)ctx->args[0],e->path2,SECOND_PATH_LOSS);
            }
        } else {
            e->aux=3;
            if(nr==NR_SYMLINK) user_path(e,(void *)ctx->args[1],-100,e->path,PATH_LOSS);
            else user_path(e,(void *)ctx->args[2],(int)ctx->args[1],e->path,PATH_LOSS);
            long n=read_user_str(e->path2,256,(void *)ctx->args[0]);
            if(n<=0) e->flags|=MEMORY_LOSS|SECOND_PATH_LOSS;
            if(n==256) e->flags|=SECOND_PATH_LOSS;
        }
    } else if(kind==CONNECT) {
        struct {u16 family,port;u8 address[4];u8 pad[8];} v4={};
        struct {u16 family,port;u32 flow;u8 address[16];u32 scope;} v6={};
        void *addr=(void *)ctx->args[1];
        if(ctx->args[2]<2||read_user(&e->family,2,addr)) e->flags|=MEMORY_LOSS;
        if(e->family==2 && ctx->args[2]>=16) {
            if(read_user(&v4,sizeof(v4),addr)) e->flags|=MEMORY_LOSS;
            __builtin_memcpy(e->address,v4.address,4);e->port=__builtin_bswap16(v4.port);
        } else if(e->family==10 && ctx->args[2]>=28) {
            if(read_user(&v6,sizeof(v6),addr)) e->flags|=MEMORY_LOSS;
            __builtin_memcpy(e->address,v6.address,16);e->port=__builtin_bswap16(v6.port);e->aux=v6.scope;
        } else if(e->family==2||e->family==10) e->flags|=MEMORY_LOSS;
        struct file *f=get_file((u32)ctx->args[0]); struct socket *socket=NULL; struct sock *sk=NULL; u16 protocol=0;
        if(f) {struct inode *inode=NULL;u16 mode=0;READ(inode,f->f_inode);if(inode) READ(mode,inode->i_mode);
            if((mode&0170000)==0140000) READ(socket,f->private_data);}
        if(socket) READ(sk,socket->sk);
        if(sk) READ(protocol,sk->sk_protocol);
        e->protocol=protocol;
    } else {e->aux=(u32)nr;}
    if(map_update(&pending,&tid,e,0)) count(LOST_MAP);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit") int on_return(struct sys_exit *ctx) {
    u32 tid=(u32)pid_tgid(); struct event *e=map_lookup(&pending,&tid);
    if(!e) return 0;
    e->result=ctx->ret;
    if(e->kind==EXEC) {map_delete(&pending,&tid);return 0;} // success emitted at sched_exec
    if(e->kind==OPEN && ctx->ret>=0) {
        fd_path(e,(u32)ctx->ret);
        struct file *f=get_file((u32)ctx->ret);u32 mode=0;
        if(f) READ(mode,f->f_mode);
        if(mode & 0x100000) e->flags|=CREATED; // FMODE_CREATED
    }
    if(e->kind==UNSUPPORTED && ctx->ret>=0) count(LOST_UNSUPPORTED);
    if(e->kind==LOAD && ctx->ret>=0 && (e->aux&2) && (e->reserved&1)) count(LOST_UNSUPPORTED);
    // Failed file calls remain raw events. Non-files (pipes, sockets, tty) do
    // not become file read/write effects and need no path-loss diagnostic.
    if((e->kind==WRITE||e->kind==READ_FILE) && !(e->flags&REGULAR) && !e->aux) {map_delete(&pending,&tid);return 0;}
    if(e->kind==CONNECT && e->family!=2 && e->family!=10) {map_delete(&pending,&tid);return 0;}
    emit(e);map_delete(&pending,&tid);return 0;
}
char LICENSE[] SEC("license")="Dual MIT/GPL";
