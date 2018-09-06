#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/types.h> /* for pid_t */
#include <sys/wait.h>  /* for wait */
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <elf.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <syscall.h>

#define PACK_RAW(event_num, umask_value) ((umask_value<<0x8) + event_num)

#define RETIRED_BRANCES 0x88
#define MISPREDICTED_BRANCES 0x89
#define RET_MASK 0x88

#define RET_THRESHOLD 20
#define WARN_THRESHOLD 30.0

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

struct read_format
{
    uint64_t nr;
    struct
    {
        uint64_t value;
        uint64_t id;
    } values[];
};

struct i386_user_regs_struct
{
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t eax;
    uint32_t xds;
    uint32_t xes;
    uint32_t xfs;
    uint32_t xgs;
    uint32_t orig_eax;
    uint32_t eip;
    uint32_t xcs;
    uint32_t eflags;
    uint32_t esp;
    uint32_t xss;
};

static long
perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                int cpu, int group_fd, unsigned long flags)
{
    int ret;
    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
    return ret;
}

int init_event_listener(struct perf_event_attr *pe, uint64_t type, uint64_t config, pid_t pid, int group_fd)
{
    memset(pe, 0, sizeof(struct perf_event_attr));
    pe->type = type;
    pe->size = sizeof(struct perf_event_attr);
    pe->config = config;
    pe->read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
    pe->disabled = 1;
    pe->exclude_kernel = 1;
    pe->exclude_hv = 1;
    return perf_event_open(pe, pid, -1, group_fd, 0);
}

uint64_t get_value(struct read_format *rf, uint64_t id)
{
    int i;
    for (i = 0; i < rf->nr; i++) {
        if (rf->values[i].id == id) {
            return rf->values[i].value;
        }
    }
    return 0;
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}

const char *callname(long call);
const char *callname32(long call);

int trace_child(pid_t child)
{
    struct perf_event_attr pe;
    int fd1, fd2;
    int ret;
    int status;
    uint64_t retired_ret_id, mispredicted_ret_id;
    uint64_t retired_rets=0, mispredicted_rets=0;
    double misprediction_rate = 0.0;
    char buf[4096];
    struct read_format *rf = (struct read_format *)buf;

    // format numbers to 1.000.000 like
    setlocale(LC_NUMERIC, "");

    fd1 = init_event_listener(&pe, PERF_TYPE_RAW, PACK_RAW(RETIRED_BRANCES, RET_MASK), child, -1);
    if (fd1 == -1)
    {
        fprintf(stderr, "Error opening leader %llx\n", pe.config);
        exit(EXIT_FAILURE);
    }
    ioctl(fd1, PERF_EVENT_IOC_ID, &retired_ret_id);

    fd2 = init_event_listener(&pe, PERF_TYPE_RAW, PACK_RAW(MISPREDICTED_BRANCES, RET_MASK), child, fd1);
    if (fd2 == -1)
    {
        fprintf(stderr, "Error opening second event %llx\n", pe.config);
        exit(EXIT_FAILURE);
    }
    ioctl(fd2, PERF_EVENT_IOC_ID, &mispredicted_ret_id);

    ioctl(fd1, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(fd1, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

    // wait for first sigstop
    waitpid(child, &status, 0);
    // set syscall trace
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    while (!wait_for_syscall(child))
    {

        union {
            struct user_regs_struct x86_64_r;
            struct i386_user_regs_struct i386_r;
        } regs;
        struct iovec {
            .iov_base = &regs,
            .iov_len = sizeof(regs)
        } x86_io;
        //ptrace(PTRACE_GETREGS, child, NULL, &regs);
        ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &x86_io);
        if (x86_io.iov_len == sizeof(struct i386_user_regs_struct)) {
            // this is a 32-bit process
            fprintf(stderr, ANSI_COLOR_BLUE "%s()" ANSI_COLOR_RESET "\n", callname32(regs.orig_eax));
        } else {
            fprintf(stderr, ANSI_COLOR_CYAN "%s()" ANSI_COLOR_RESET "\n", callname(regs.orig_rax));
        }

        ioctl(fd1, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
        ret = read(fd1, buf, sizeof(buf));
        if (ret == -1)
        {
            fprintf(stderr, "Error reading events: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        retired_rets = get_value(rf, retired_ret_id);
        mispredicted_rets = get_value(rf, mispredicted_ret_id);


        //printf("%lu events read:\n", rf->nr);
        // Taken speculative and retired indirect branches that are returns.
        printf("%'lu returns\n", retired_rets);
        // Taken speculative and retired mispredicted indirect branches that are returns.
        printf("%'lu mispredicted returns\n", mispredicted_rets);

        if (retired_rets > RET_THRESHOLD)
        {
            misprediction_rate = (((double) mispredicted_rets) / retired_rets) * 100;
            if (misprediction_rate > WARN_THRESHOLD)
                printf(ANSI_COLOR_RED "%.1lf%% misprediction" ANSI_COLOR_RESET "\n", misprediction_rate);
            else
                printf(ANSI_COLOR_GREEN "%.1lf%% misprediction" ANSI_COLOR_RESET "\n", misprediction_rate);
        }

        ioctl(fd1, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
        ioctl(fd1, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        if (wait_for_syscall(child) != 0)
            break;
    }

    close(fd2);
    close(fd1);
    return 0;
}

    int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <cmd>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    /*Spawn a child to run the program.*/
    pid_t pid = fork();
    if (pid == 0)
    { /* child process */
        extern char **environ;
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        execve(argv[1], &argv[1], environ);
        fprintf(stderr, "Execv failed: %s\n", strerror(errno));
        exit(127); /* only if execv fails */
    }
    else
    { /* pid!=0; parent process */
        return trace_child(pid);
    }
}

/* callname */

static char *callname_buf[256];

const char *callname32(long call)
{
    switch (call)
    {
    case 0:
        return "restart_syscall";
    case 1:
        return "exit";
    case 2:
        return "fork";
    case 3:
        return "read";
    case 4:
        return "write";
    case 5:
        return "open";
    case 6:
        return "close";
    case 7:
        return "waitpid";
    case 8:
        return "creat";
    case 9:
        return "link";
    case 10:
        return "unlink";
    case 11:
        return "execve";
    case 12:
        return "chdir";
    case 13:
        return "time";
    case 14:
        return "mknod";
    case 15:
        return "chmod";
    case 16:
        return "lchown";
    case 17:
        return "break";
    case 18:
        return "oldstat";
    case 19:
        return "lseek";
    case 20:
        return "getpid";
    case 21:
        return "mount";
    case 22:
        return "umount";
    case 23:
        return "setuid";
    case 24:
        return "getuid";
    case 25:
        return "stime";
    case 26:
        return "ptrace";
    case 27:
        return "alarm";
    case 28:
        return "oldfstat";
    case 29:
        return "pause";
    case 30:
        return "utime";
    case 31:
        return "stty";
    case 32:
        return "gtty";
    case 33:
        return "access";
    case 34:
        return "nice";
    case 35:
        return "ftime";
    case 36:
        return "sync";
    case 37:
        return "kill";
    case 38:
        return "rename";
    case 39:
        return "mkdir";
    case 40:
        return "rmdir";
    case 41:
        return "dup";
    case 42:
        return "pipe";
    case 43:
        return "times";
    case 44:
        return "prof";
    case 45:
        return "brk";
    case 46:
        return "setgid";
    case 47:
        return "getgid";
    case 48:
        return "signal";
    case 49:
        return "geteuid";
    case 50:
        return "getegid";
    case 51:
        return "acct";
    case 52:
        return "umount2";
    case 53:
        return "lock";
    case 54:
        return "ioctl";
    case 55:
        return "fcntl";
    case 56:
        return "mpx";
    case 57:
        return "setpgid";
    case 58:
        return "ulimit";
    case 59:
        return "oldolduname";
    case 60:
        return "umask";
    case 61:
        return "chroot";
    case 62:
        return "ustat";
    case 63:
        return "dup2";
    case 64:
        return "getppid";
    case 65:
        return "getpgrp";
    case 66:
        return "setsid";
    case 67:
        return "sigaction";
    case 68:
        return "sgetmask";
    case 69:
        return "ssetmask";
    case 70:
        return "setreuid";
    case 71:
        return "setregid";
    case 72:
        return "sigsuspend";
    case 73:
        return "sigpending";
    case 74:
        return "sethostname";
    case 75:
        return "setrlimit";
    case 76:
        return "getrlimit";
    case 77:
        return "getrusage";
    case 78:
        return "gettimeofday";
    case 79:
        return "settimeofday";
    case 80:
        return "getgroups";
    case 81:
        return "setgroups";
    case 82:
        return "select";
    case 83:
        return "symlink";
    case 84:
        return "oldlstat";
    case 85:
        return "readlink";
    case 86:
        return "uselib";
    case 87:
        return "swapon";
    case 88:
        return "reboot";
    case 89:
        return "readdir";
    case 90:
        return "mmap";
    case 91:
        return "munmap";
    case 92:
        return "truncate";
    case 93:
        return "ftruncate";
    case 94:
        return "fchmod";
    case 95:
        return "fchown";
    case 96:
        return "getpriority";
    case 97:
        return "setpriority";
    case 98:
        return "profil";
    case 99:
        return "statfs";
    case 100:
        return "fstatfs";
    case 101:
        return "ioperm";
    case 102:
        return "socketcall";
    case 103:
        return "syslog";
    case 104:
        return "setitimer";
    case 105:
        return "getitimer";
    case 106:
        return "stat";
    case 107:
        return "lstat";
    case 108:
        return "fstat";
    case 109:
        return "olduname";
    case 110:
        return "iopl";
    case 111:
        return "vhangup";
    case 112:
        return "idle";
    case 113:
        return "vm86old";
    case 114:
        return "wait4";
    case 115:
        return "swapoff";
    case 116:
        return "sysinfo";
    case 117:
        return "ipc";
    case 118:
        return "fsync";
    case 119:
        return "sigreturn";
    case 120:
        return "clone";
    case 121:
        return "setdomainname";
    case 122:
        return "uname";
    case 123:
        return "modify_ldt";
    case 124:
        return "adjtimex";
    case 125:
        return "mprotect";
    case 126:
        return "sigprocmask";
    case 127:
        return "create_module";
    case 128:
        return "init_module";
    case 129:
        return "delete_module";
    case 130:
        return "get_kernel_syms";
    case 131:
        return "quotactl";
    case 132:
        return "getpgid";
    case 133:
        return "fchdir";
    case 134:
        return "bdflush";
    case 135:
        return "sysfs";
    case 136:
        return "personality";
    case 137:
        return "afs_syscall";
    case 138:
        return "setfsuid";
    case 139:
        return "setfsgid";
    case 140:
        return "_llseek";
    case 141:
        return "getdents";
    case 142:
        return "_newselect";
    case 143:
        return "flock";
    case 144:
        return "msync";
    case 145:
        return "readv";
    case 146:
        return "writev";
    case 147:
        return "getsid";
    case 148:
        return "fdatasync";
    case 149:
        return "_sysctl";
    case 150:
        return "mlock";
    case 151:
        return "munlock";
    case 152:
        return "mlockall";
    case 153:
        return "munlockall";
    case 154:
        return "sched_setparam";
    case 155:
        return "sched_getparam";
    case 156:
        return "sched_setscheduler";
    case 157:
        return "sched_getscheduler";
    case 158:
        return "sched_yield";
    case 159:
        return "sched_get_priority_max";
    case 160:
        return "sched_get_priority_min";
    case 161:
        return "sched_rr_get_interval";
    case 162:
        return "nanosleep";
    case 163:
        return "mremap";
    case 164:
        return "setresuid";
    case 165:
        return "getresuid";
    case 166:
        return "vm86";
    case 167:
        return "query_module";
    case 168:
        return "poll";
    case 169:
        return "nfsservctl";
    case 170:
        return "setresgid";
    case 171:
        return "getresgid";
    case 172:
        return "prctl";
    case 173:
        return "rt_sigreturn";
    case 174:
        return "rt_sigaction";
    case 175:
        return "rt_sigprocmask";
    case 176:
        return "rt_sigpending";
    case 177:
        return "rt_sigtimedwait";
    case 178:
        return "rt_sigqueueinfo";
    case 179:
        return "rt_sigsuspend";
    case 180:
        return "pread64";
    case 181:
        return "pwrite64";
    case 182:
        return "chown";
    case 183:
        return "getcwd";
    case 184:
        return "capget";
    case 185:
        return "capset";
    case 186:
        return "sigaltstack";
    case 187:
        return "sendfile";
    case 188:
        return "getpmsg";
    case 189:
        return "putpmsg";
    case 190:
        return "vfork";
    case 191:
        return "ugetrlimit";
    case 192:
        return "mmap2";
    case 193:
        return "truncate64";
    case 194:
        return "ftruncate64";
    case 195:
        return "stat64";
    case 196:
        return "lstat64";
    case 197:
        return "fstat64";
    case 198:
        return "lchown32";
    case 199:
        return "getuid32";
    case 200:
        return "getgid32";
    case 201:
        return "geteuid32";
    case 202:
        return "getegid32";
    case 203:
        return "setreuid32";
    case 204:
        return "setregid32";
    case 205:
        return "getgroups32";
    case 206:
        return "setgroups32";
    case 207:
        return "fchown32";
    case 208:
        return "setresuid32";
    case 209:
        return "getresuid32";
    case 210:
        return "setresgid32";
    case 211:
        return "getresgid32";
    case 212:
        return "chown32";
    case 213:
        return "setuid32";
    case 214:
        return "setgid32";
    case 215:
        return "setfsuid32";
    case 216:
        return "setfsgid32";
    case 217:
        return "pivot_root";
    case 218:
        return "mincore";
    case 219:
        return "madvise";
    case 220:
        return "getdents64";
    case 221:
        return "fcntl64";
    case 224:
        return "gettid";
    case 225:
        return "readahead";
    case 226:
        return "setxattr";
    case 227:
        return "lsetxattr";
    case 228:
        return "fsetxattr";
    case 229:
        return "getxattr";
    case 230:
        return "lgetxattr";
    case 231:
        return "fgetxattr";
    case 232:
        return "listxattr";
    case 233:
        return "llistxattr";
    case 234:
        return "flistxattr";
    case 235:
        return "removexattr";
    case 236:
        return "lremovexattr";
    case 237:
        return "fremovexattr";
    case 238:
        return "tkill";
    case 239:
        return "sendfile64";
    case 240:
        return "futex";
    case 241:
        return "sched_setaffinity";
    case 242:
        return "sched_getaffinity";
    case 243:
        return "set_thread_area";
    case 244:
        return "get_thread_area";
    case 245:
        return "io_setup";
    case 246:
        return "io_destroy";
    case 247:
        return "io_getevents";
    case 248:
        return "io_submit";
    case 249:
        return "io_cancel";
    case 250:
        return "fadvise64";
    case 252:
        return "exit_group";
    case 253:
        return "lookup_dcookie";
    case 254:
        return "epoll_create";
    case 255:
        return "epoll_ctl";
    case 256:
        return "epoll_wait";
    case 257:
        return "remap_file_pages";
    case 258:
        return "set_tid_address";
    case 259:
        return "timer_create";
    case 260:
        return "timer_settime";
    case 261:
        return "timer_gettime";
    case 262:
        return "timer_getoverrun";
    case 263:
        return "timer_delete";
    case 264:
        return "clock_settime";
    case 265:
        return "clock_gettime";
    case 266:
        return "clock_getres";
    case 267:
        return "clock_nanosleep";
    case 268:
        return "statfs64";
    case 269:
        return "fstatfs64";
    case 270:
        return "tgkill";
    case 271:
        return "utimes";
    case 272:
        return "fadvise64_64";
    case 273:
        return "vserver";
    case 274:
        return "mbind";
    case 275:
        return "get_mempolicy";
    case 276:
        return "set_mempolicy";
    case 277:
        return "mq_open";
    case 278:
        return "mq_unlink";
    case 279:
        return "mq_timedsend";
    case 280:
        return "mq_timedreceive";
    case 281:
        return "mq_notify";
    case 282:
        return "mq_getsetattr";
    case 283:
        return "kexec_load";
    case 284:
        return "waitid";
    case 286:
        return "add_key";
    case 287:
        return "request_key";
    case 288:
        return "keyctl";
    case 289:
        return "ioprio_set";
    case 290:
        return "ioprio_get";
    case 291:
        return "inotify_init";
    case 292:
        return "inotify_add_watch";
    case 293:
        return "inotify_rm_watch";
    case 294:
        return "migrate_pages";
    case 295:
        return "openat";
    case 296:
        return "mkdirat";
    case 297:
        return "mknodat";
    case 298:
        return "fchownat";
    case 299:
        return "futimesat";
    case 300:
        return "fstatat64";
    case 301:
        return "unlinkat";
    case 302:
        return "renameat";
    case 303:
        return "linkat";
    case 304:
        return "symlinkat";
    case 305:
        return "readlinkat";
    case 306:
        return "fchmodat";
    case 307:
        return "faccessat";
    case 308:
        return "pselect6";
    case 309:
        return "ppoll";
    case 310:
        return "unshare";
    case 311:
        return "set_robust_list";
    case 312:
        return "get_robust_list";
    case 313:
        return "splice";
    case 314:
        return "sync_file_range";
    case 315:
        return "tee";
    case 316:
        return "vmsplice";
    case 317:
        return "move_pages";
    case 318:
        return "getcpu";
    case 319:
        return "epoll_pwait";
    case 320:
        return "utimensat";
    case 321:
        return "signalfd";
    case 322:
        return "timerfd_create";
    case 323:
        return "eventfd";
    case 324:
        return "fallocate";
    case 325:
        return "timerfd_settime";
    case 326:
        return "timerfd_gettime";
    case 327:
        return "signalfd4";
    case 328:
        return "eventfd2";
    case 329:
        return "epoll_create1";
    case 330:
        return "dup3";
    case 331:
        return "pipe2";
    case 332:
        return "inotify_init1";
    case 333:
        return "preadv";
    case 334:
        return "pwritev";
    case 335:
        return "rt_tgsigqueueinfo";
    case 336:
        return "perf_event_open";
    case 337:
        return "recvmmsg";
    case 338:
        return "fanotify_init";
    case 339:
        return "fanotify_mark";
    case 340:
        return "prlimit64";
    case 341:
        return "name_to_handle_at";
    case 342:
        return "open_by_handle_at";
    case 343:
        return "clock_adjtime";
    case 344:
        return "syncfs";
    case 345:
        return "sendmmsg";
    case 346:
        return "setns";
    case 347:
        return "process_vm_readv";
    case 348:
        return "process_vm_writev";
    case 349:
        return "kcmp";
    case 350:
        return "finit_module";
    case 351:
        return "sched_setattr";
    case 352:
        return "sched_getattr";
    case 353:
        return "renameat2";
    case 354:
        return "seccomp";
    case 355:
        return "getrandom";
    case 356:
        return "memfd_create";
    case 357:
        return "bpf";
    case 358:
        return "execveat";
    case 359:
        return "socket";
    case 360:
        return "socketpair";
    case 361:
        return "bind";
    case 362:
        return "connect";
    case 363:
        return "listen";
    case 364:
        return "accept4";
    case 365:
        return "getsockopt";
    case 366:
        return "setsockopt";
    case 367:
        return "getsockname";
    case 368:
        return "getpeername";
    case 369:
        return "sendto";
    case 370:
        return "sendmsg";
    case 371:
        return "recvfrom";
    case 372:
        return "recvmsg";
    case 373:
        return "shutdown";
    case 374:
        return "userfaultfd";
    case 375:
        return "membarrier";
    case 376:
        return "mlock2";
    case 377:
        return "copy_file_range";
    case 378:
        return "preadv2";
    case 379:
        return "pwritev2";
    case 380:
        return "pkey_mprotect";
    case 381:
        return "pkey_alloc";
    case 382:
        return "pkey_free";
    case 383:
        return "statx";
    case 384:
        return "arch_prctl";
    case 385:
        return "io_pgetevents";
    case 386:
        return "rseq";
    default:
        return "unknown";
    }
}

const char *callname(long call)
{
    switch (call)
    {

#ifdef SYS__sysctl
    case SYS__sysctl:
        return "_sysctl";
#endif

#ifdef SYS_access
    case SYS_access:
        return "access";
#endif

#ifdef SYS_acct
    case SYS_acct:
        return "acct";
#endif

#ifdef SYS_add_key
    case SYS_add_key:
        return "add_key";
#endif

#ifdef SYS_adjtimex
    case SYS_adjtimex:
        return "adjtimex";
#endif

#ifdef SYS_afs_syscall
    case SYS_afs_syscall:
        return "afs_syscall";
#endif

#ifdef SYS_alarm
    case SYS_alarm:
        return "alarm";
#endif

#ifdef SYS_brk
    case SYS_brk:
        return "brk";
#endif

#ifdef SYS_capget
    case SYS_capget:
        return "capget";
#endif

#ifdef SYS_capset
    case SYS_capset:
        return "capset";
#endif

#ifdef SYS_chdir
    case SYS_chdir:
        return "chdir";
#endif

#ifdef SYS_chmod
    case SYS_chmod:
        return "chmod";
#endif

#ifdef SYS_chown
    case SYS_chown:
        return "chown";
#endif

#ifdef SYS_chroot
    case SYS_chroot:
        return "chroot";
#endif

#ifdef SYS_clock_getres
    case SYS_clock_getres:
        return "clock_getres";
#endif

#ifdef SYS_clock_gettime
    case SYS_clock_gettime:
        return "clock_gettime";
#endif

#ifdef SYS_clock_nanosleep
    case SYS_clock_nanosleep:
        return "clock_nanosleep";
#endif

#ifdef SYS_clock_settime
    case SYS_clock_settime:
        return "clock_settime";
#endif

#ifdef SYS_clone
    case SYS_clone:
        return "clone";
#endif

#ifdef SYS_close
    case SYS_close:
        return "close";
#endif

#ifdef SYS_creat
    case SYS_creat:
        return "creat";
#endif

#ifdef SYS_create_module
    case SYS_create_module:
        return "create_module";
#endif

#ifdef SYS_delete_module
    case SYS_delete_module:
        return "delete_module";
#endif

#ifdef SYS_dup
    case SYS_dup:
        return "dup";
#endif

#ifdef SYS_dup2
    case SYS_dup2:
        return "dup2";
#endif

#ifdef SYS_epoll_create
    case SYS_epoll_create:
        return "epoll_create";
#endif

#ifdef SYS_epoll_ctl
    case SYS_epoll_ctl:
        return "epoll_ctl";
#endif

#ifdef SYS_epoll_pwait
    case SYS_epoll_pwait:
        return "epoll_pwait";
#endif

#ifdef SYS_epoll_wait
    case SYS_epoll_wait:
        return "epoll_wait";
#endif

#ifdef SYS_eventfd
    case SYS_eventfd:
        return "eventfd";
#endif

#ifdef SYS_execve
    case SYS_execve:
        return "execve";
#endif

#ifdef SYS_exit
    case SYS_exit:
        return "exit";
#endif

#ifdef SYS_exit_group
    case SYS_exit_group:
        return "exit_group";
#endif

#ifdef SYS_faccessat
    case SYS_faccessat:
        return "faccessat";
#endif

#ifdef SYS_fadvise64
    case SYS_fadvise64:
        return "fadvise64";
#endif

#ifdef SYS_fallocate
    case SYS_fallocate:
        return "fallocate";
#endif

#ifdef SYS_fchdir
    case SYS_fchdir:
        return "fchdir";
#endif

#ifdef SYS_fchmod
    case SYS_fchmod:
        return "fchmod";
#endif

#ifdef SYS_fchmodat
    case SYS_fchmodat:
        return "fchmodat";
#endif

#ifdef SYS_fchown
    case SYS_fchown:
        return "fchown";
#endif

#ifdef SYS_fchownat
    case SYS_fchownat:
        return "fchownat";
#endif

#ifdef SYS_fcntl
    case SYS_fcntl:
        return "fcntl";
#endif

#ifdef SYS_fdatasync
    case SYS_fdatasync:
        return "fdatasync";
#endif

#ifdef SYS_fgetxattr
    case SYS_fgetxattr:
        return "fgetxattr";
#endif

#ifdef SYS_flistxattr
    case SYS_flistxattr:
        return "flistxattr";
#endif

#ifdef SYS_flock
    case SYS_flock:
        return "flock";
#endif

#ifdef SYS_fork
    case SYS_fork:
        return "fork";
#endif

#ifdef SYS_fremovexattr
    case SYS_fremovexattr:
        return "fremovexattr";
#endif

#ifdef SYS_fsetxattr
    case SYS_fsetxattr:
        return "fsetxattr";
#endif

#ifdef SYS_fstat
    case SYS_fstat:
        return "fstat";
#endif

#ifdef SYS_fstatfs
    case SYS_fstatfs:
        return "fstatfs";
#endif

#ifdef SYS_fsync
    case SYS_fsync:
        return "fsync";
#endif

#ifdef SYS_ftruncate
    case SYS_ftruncate:
        return "ftruncate";
#endif

#ifdef SYS_futex
    case SYS_futex:
        return "futex";
#endif

#ifdef SYS_futimesat
    case SYS_futimesat:
        return "futimesat";
#endif

#ifdef SYS_get_kernel_syms
    case SYS_get_kernel_syms:
        return "get_kernel_syms";
#endif

#ifdef SYS_get_mempolicy
    case SYS_get_mempolicy:
        return "get_mempolicy";
#endif

#ifdef SYS_get_robust_list
    case SYS_get_robust_list:
        return "get_robust_list";
#endif

#ifdef SYS_get_thread_area
    case SYS_get_thread_area:
        return "get_thread_area";
#endif

#ifdef SYS_getcwd
    case SYS_getcwd:
        return "getcwd";
#endif

#ifdef SYS_getdents
    case SYS_getdents:
        return "getdents";
#endif

#ifdef SYS_getdents64
    case SYS_getdents64:
        return "getdents64";
#endif

#ifdef SYS_getegid
    case SYS_getegid:
        return "getegid";
#endif

#ifdef SYS_geteuid
    case SYS_geteuid:
        return "geteuid";
#endif

#ifdef SYS_getgid
    case SYS_getgid:
        return "getgid";
#endif

#ifdef SYS_getgroups
    case SYS_getgroups:
        return "getgroups";
#endif

#ifdef SYS_getitimer
    case SYS_getitimer:
        return "getitimer";
#endif

#ifdef SYS_getpgid
    case SYS_getpgid:
        return "getpgid";
#endif

#ifdef SYS_getpgrp
    case SYS_getpgrp:
        return "getpgrp";
#endif

#ifdef SYS_getpid
    case SYS_getpid:
        return "getpid";
#endif

#ifdef SYS_getpmsg
    case SYS_getpmsg:
        return "getpmsg";
#endif

#ifdef SYS_getppid
    case SYS_getppid:
        return "getppid";
#endif

#ifdef SYS_getpriority
    case SYS_getpriority:
        return "getpriority";
#endif

#ifdef SYS_getresgid
    case SYS_getresgid:
        return "getresgid";
#endif

#ifdef SYS_getresuid
    case SYS_getresuid:
        return "getresuid";
#endif

#ifdef SYS_getrlimit
    case SYS_getrlimit:
        return "getrlimit";
#endif

#ifdef SYS_getrusage
    case SYS_getrusage:
        return "getrusage";
#endif

#ifdef SYS_getsid
    case SYS_getsid:
        return "getsid";
#endif

#ifdef SYS_gettid
    case SYS_gettid:
        return "gettid";
#endif

#ifdef SYS_gettimeofday
    case SYS_gettimeofday:
        return "gettimeofday";
#endif

#ifdef SYS_getuid
    case SYS_getuid:
        return "getuid";
#endif

#ifdef SYS_getxattr
    case SYS_getxattr:
        return "getxattr";
#endif

#ifdef SYS_init_module
    case SYS_init_module:
        return "init_module";
#endif

#ifdef SYS_inotify_add_watch
    case SYS_inotify_add_watch:
        return "inotify_add_watch";
#endif

#ifdef SYS_inotify_init
    case SYS_inotify_init:
        return "inotify_init";
#endif

#ifdef SYS_inotify_rm_watch
    case SYS_inotify_rm_watch:
        return "inotify_rm_watch";
#endif

#ifdef SYS_io_cancel
    case SYS_io_cancel:
        return "io_cancel";
#endif

#ifdef SYS_io_destroy
    case SYS_io_destroy:
        return "io_destroy";
#endif

#ifdef SYS_io_getevents
    case SYS_io_getevents:
        return "io_getevents";
#endif

#ifdef SYS_io_setup
    case SYS_io_setup:
        return "io_setup";
#endif

#ifdef SYS_io_submit
    case SYS_io_submit:
        return "io_submit";
#endif

#ifdef SYS_ioctl
    case SYS_ioctl:
        return "ioctl";
#endif

#ifdef SYS_ioperm
    case SYS_ioperm:
        return "ioperm";
#endif

#ifdef SYS_iopl
    case SYS_iopl:
        return "iopl";
#endif

#ifdef SYS_ioprio_get
    case SYS_ioprio_get:
        return "ioprio_get";
#endif

#ifdef SYS_ioprio_set
    case SYS_ioprio_set:
        return "ioprio_set";
#endif

#ifdef SYS_kexec_load
    case SYS_kexec_load:
        return "kexec_load";
#endif

#ifdef SYS_keyctl
    case SYS_keyctl:
        return "keyctl";
#endif

#ifdef SYS_kill
    case SYS_kill:
        return "kill";
#endif

#ifdef SYS_lchown
    case SYS_lchown:
        return "lchown";
#endif

#ifdef SYS_lgetxattr
    case SYS_lgetxattr:
        return "lgetxattr";
#endif

#ifdef SYS_link
    case SYS_link:
        return "link";
#endif

#ifdef SYS_linkat
    case SYS_linkat:
        return "linkat";
#endif

#ifdef SYS_listxattr
    case SYS_listxattr:
        return "listxattr";
#endif

#ifdef SYS_llistxattr
    case SYS_llistxattr:
        return "llistxattr";
#endif

#ifdef SYS_lookup_dcookie
    case SYS_lookup_dcookie:
        return "lookup_dcookie";
#endif

#ifdef SYS_lremovexattr
    case SYS_lremovexattr:
        return "lremovexattr";
#endif

#ifdef SYS_lseek
    case SYS_lseek:
        return "lseek";
#endif

#ifdef SYS_lsetxattr
    case SYS_lsetxattr:
        return "lsetxattr";
#endif

#ifdef SYS_lstat
    case SYS_lstat:
        return "lstat";
#endif

#ifdef SYS_madvise
    case SYS_madvise:
        return "madvise";
#endif

#ifdef SYS_mbind
    case SYS_mbind:
        return "mbind";
#endif

#ifdef SYS_migrate_pages
    case SYS_migrate_pages:
        return "migrate_pages";
#endif

#ifdef SYS_mincore
    case SYS_mincore:
        return "mincore";
#endif

#ifdef SYS_mkdir
    case SYS_mkdir:
        return "mkdir";
#endif

#ifdef SYS_mkdirat
    case SYS_mkdirat:
        return "mkdirat";
#endif

#ifdef SYS_mknod
    case SYS_mknod:
        return "mknod";
#endif

#ifdef SYS_mknodat
    case SYS_mknodat:
        return "mknodat";
#endif

#ifdef SYS_mlock
    case SYS_mlock:
        return "mlock";
#endif

#ifdef SYS_mlockall
    case SYS_mlockall:
        return "mlockall";
#endif

#ifdef SYS_mmap
    case SYS_mmap:
        return "mmap";
#endif

#ifdef SYS_modify_ldt
    case SYS_modify_ldt:
        return "modify_ldt";
#endif

#ifdef SYS_mount
    case SYS_mount:
        return "mount";
#endif

#ifdef SYS_move_pages
    case SYS_move_pages:
        return "move_pages";
#endif

#ifdef SYS_mprotect
    case SYS_mprotect:
        return "mprotect";
#endif

#ifdef SYS_mq_getsetattr
    case SYS_mq_getsetattr:
        return "mq_getsetattr";
#endif

#ifdef SYS_mq_notify
    case SYS_mq_notify:
        return "mq_notify";
#endif

#ifdef SYS_mq_open
    case SYS_mq_open:
        return "mq_open";
#endif

#ifdef SYS_mq_timedreceive
    case SYS_mq_timedreceive:
        return "mq_timedreceive";
#endif

#ifdef SYS_mq_timedsend
    case SYS_mq_timedsend:
        return "mq_timedsend";
#endif

#ifdef SYS_mq_unlink
    case SYS_mq_unlink:
        return "mq_unlink";
#endif

#ifdef SYS_mremap
    case SYS_mremap:
        return "mremap";
#endif

#ifdef SYS_msync
    case SYS_msync:
        return "msync";
#endif

#ifdef SYS_munlock
    case SYS_munlock:
        return "munlock";
#endif

#ifdef SYS_munlockall
    case SYS_munlockall:
        return "munlockall";
#endif

#ifdef SYS_munmap
    case SYS_munmap:
        return "munmap";
#endif

#ifdef SYS_nanosleep
    case SYS_nanosleep:
        return "nanosleep";
#endif

#ifdef SYS_nfsservctl
    case SYS_nfsservctl:
        return "nfsservctl";
#endif

#ifdef SYS_open
    case SYS_open:
        return "open";
#endif

#ifdef SYS_openat
    case SYS_openat:
        return "openat";
#endif

#ifdef SYS_pause
    case SYS_pause:
        return "pause";
#endif

#ifdef SYS_personality
    case SYS_personality:
        return "personality";
#endif

#ifdef SYS_pipe
    case SYS_pipe:
        return "pipe";
#endif

#ifdef SYS_pivot_root
    case SYS_pivot_root:
        return "pivot_root";
#endif

#ifdef SYS_poll
    case SYS_poll:
        return "poll";
#endif

#ifdef SYS_ppoll
    case SYS_ppoll:
        return "ppoll";
#endif

#ifdef SYS_prctl
    case SYS_prctl:
        return "prctl";
#endif

#ifdef SYS_pread64
    case SYS_pread64:
        return "pread64";
#endif

#ifdef SYS_pselect6
    case SYS_pselect6:
        return "pselect6";
#endif

#ifdef SYS_ptrace
    case SYS_ptrace:
        return "ptrace";
#endif

#ifdef SYS_putpmsg
    case SYS_putpmsg:
        return "putpmsg";
#endif

#ifdef SYS_pwrite64
    case SYS_pwrite64:
        return "pwrite64";
#endif

#ifdef SYS_query_module
    case SYS_query_module:
        return "query_module";
#endif

#ifdef SYS_quotactl
    case SYS_quotactl:
        return "quotactl";
#endif

#ifdef SYS_read
    case SYS_read:
        return "read";
#endif

#ifdef SYS_readahead
    case SYS_readahead:
        return "readahead";
#endif

#ifdef SYS_readlink
    case SYS_readlink:
        return "readlink";
#endif

#ifdef SYS_readlinkat
    case SYS_readlinkat:
        return "readlinkat";
#endif

#ifdef SYS_readv
    case SYS_readv:
        return "readv";
#endif

#ifdef SYS_reboot
    case SYS_reboot:
        return "reboot";
#endif

#ifdef SYS_remap_file_pages
    case SYS_remap_file_pages:
        return "remap_file_pages";
#endif

#ifdef SYS_removexattr
    case SYS_removexattr:
        return "removexattr";
#endif

#ifdef SYS_rename
    case SYS_rename:
        return "rename";
#endif

#ifdef SYS_renameat
    case SYS_renameat:
        return "renameat";
#endif

#ifdef SYS_request_key
    case SYS_request_key:
        return "request_key";
#endif

#ifdef SYS_restart_syscall
    case SYS_restart_syscall:
        return "restart_syscall";
#endif

#ifdef SYS_rmdir
    case SYS_rmdir:
        return "rmdir";
#endif

#ifdef SYS_rt_sigaction
    case SYS_rt_sigaction:
        return "rt_sigaction";
#endif

#ifdef SYS_rt_sigpending
    case SYS_rt_sigpending:
        return "rt_sigpending";
#endif

#ifdef SYS_rt_sigprocmask
    case SYS_rt_sigprocmask:
        return "rt_sigprocmask";
#endif

#ifdef SYS_rt_sigqueueinfo
    case SYS_rt_sigqueueinfo:
        return "rt_sigqueueinfo";
#endif

#ifdef SYS_rt_sigreturn
    case SYS_rt_sigreturn:
        return "rt_sigreturn";
#endif

#ifdef SYS_rt_sigsuspend
    case SYS_rt_sigsuspend:
        return "rt_sigsuspend";
#endif

#ifdef SYS_rt_sigtimedwait
    case SYS_rt_sigtimedwait:
        return "rt_sigtimedwait";
#endif

#ifdef SYS_sched_get_priority_max
    case SYS_sched_get_priority_max:
        return "sched_get_priority_max";
#endif

#ifdef SYS_sched_get_priority_min
    case SYS_sched_get_priority_min:
        return "sched_get_priority_min";
#endif

#ifdef SYS_sched_getaffinity
    case SYS_sched_getaffinity:
        return "sched_getaffinity";
#endif

#ifdef SYS_sched_getparam
    case SYS_sched_getparam:
        return "sched_getparam";
#endif

#ifdef SYS_sched_getscheduler
    case SYS_sched_getscheduler:
        return "sched_getscheduler";
#endif

#ifdef SYS_sched_rr_get_interval
    case SYS_sched_rr_get_interval:
        return "sched_rr_get_interval";
#endif

#ifdef SYS_sched_setaffinity
    case SYS_sched_setaffinity:
        return "sched_setaffinity";
#endif

#ifdef SYS_sched_setparam
    case SYS_sched_setparam:
        return "sched_setparam";
#endif

#ifdef SYS_sched_setscheduler
    case SYS_sched_setscheduler:
        return "sched_setscheduler";
#endif

#ifdef SYS_sched_yield
    case SYS_sched_yield:
        return "sched_yield";
#endif

#ifdef SYS_select
    case SYS_select:
        return "select";
#endif

#ifdef SYS_sendfile
    case SYS_sendfile:
        return "sendfile";
#endif

#ifdef SYS_set_mempolicy
    case SYS_set_mempolicy:
        return "set_mempolicy";
#endif

#ifdef SYS_set_robust_list
    case SYS_set_robust_list:
        return "set_robust_list";
#endif

#ifdef SYS_set_thread_area
    case SYS_set_thread_area:
        return "set_thread_area";
#endif

#ifdef SYS_set_tid_address
    case SYS_set_tid_address:
        return "set_tid_address";
#endif

#ifdef SYS_setdomainname
    case SYS_setdomainname:
        return "setdomainname";
#endif

#ifdef SYS_setfsgid
    case SYS_setfsgid:
        return "setfsgid";
#endif

#ifdef SYS_setfsuid
    case SYS_setfsuid:
        return "setfsuid";
#endif

#ifdef SYS_setgid
    case SYS_setgid:
        return "setgid";
#endif

#ifdef SYS_setgroups
    case SYS_setgroups:
        return "setgroups";
#endif

#ifdef SYS_sethostname
    case SYS_sethostname:
        return "sethostname";
#endif

#ifdef SYS_setitimer
    case SYS_setitimer:
        return "setitimer";
#endif

#ifdef SYS_setpgid
    case SYS_setpgid:
        return "setpgid";
#endif

#ifdef SYS_setpriority
    case SYS_setpriority:
        return "setpriority";
#endif

#ifdef SYS_setregid
    case SYS_setregid:
        return "setregid";
#endif

#ifdef SYS_setresgid
    case SYS_setresgid:
        return "setresgid";
#endif

#ifdef SYS_setresuid
    case SYS_setresuid:
        return "setresuid";
#endif

#ifdef SYS_setreuid
    case SYS_setreuid:
        return "setreuid";
#endif

#ifdef SYS_setrlimit
    case SYS_setrlimit:
        return "setrlimit";
#endif

#ifdef SYS_setsid
    case SYS_setsid:
        return "setsid";
#endif

#ifdef SYS_settimeofday
    case SYS_settimeofday:
        return "settimeofday";
#endif

#ifdef SYS_setuid
    case SYS_setuid:
        return "setuid";
#endif

#ifdef SYS_setxattr
    case SYS_setxattr:
        return "setxattr";
#endif

#ifdef SYS_sigaltstack
    case SYS_sigaltstack:
        return "sigaltstack";
#endif

#ifdef SYS_signalfd
    case SYS_signalfd:
        return "signalfd";
#endif

#ifdef SYS_splice
    case SYS_splice:
        return "splice";
#endif

#ifdef SYS_stat
    case SYS_stat:
        return "stat";
#endif

#ifdef SYS_statfs
    case SYS_statfs:
        return "statfs";
#endif

#ifdef SYS_swapoff
    case SYS_swapoff:
        return "swapoff";
#endif

#ifdef SYS_swapon
    case SYS_swapon:
        return "swapon";
#endif

#ifdef SYS_symlink
    case SYS_symlink:
        return "symlink";
#endif

#ifdef SYS_symlinkat
    case SYS_symlinkat:
        return "symlinkat";
#endif

#ifdef SYS_sync
    case SYS_sync:
        return "sync";
#endif

#ifdef SYS_sync_file_range
    case SYS_sync_file_range:
        return "sync_file_range";
#endif

#ifdef SYS_sysfs
    case SYS_sysfs:
        return "sysfs";
#endif

#ifdef SYS_sysinfo
    case SYS_sysinfo:
        return "sysinfo";
#endif

#ifdef SYS_syslog
    case SYS_syslog:
        return "syslog";
#endif

#ifdef SYS_tee
    case SYS_tee:
        return "tee";
#endif

#ifdef SYS_tgkill
    case SYS_tgkill:
        return "tgkill";
#endif

#ifdef SYS_time
    case SYS_time:
        return "time";
#endif

#ifdef SYS_timer_create
    case SYS_timer_create:
        return "timer_create";
#endif

#ifdef SYS_timer_delete
    case SYS_timer_delete:
        return "timer_delete";
#endif

#ifdef SYS_timer_getoverrun
    case SYS_timer_getoverrun:
        return "timer_getoverrun";
#endif

#ifdef SYS_timer_gettime
    case SYS_timer_gettime:
        return "timer_gettime";
#endif

#ifdef SYS_timer_settime
    case SYS_timer_settime:
        return "timer_settime";
#endif

#ifdef SYS_timerfd_create
    case SYS_timerfd_create:
        return "timerfd_create";
#endif

#ifdef SYS_timerfd_gettime
    case SYS_timerfd_gettime:
        return "timerfd_gettime";
#endif

#ifdef SYS_timerfd_settime
    case SYS_timerfd_settime:
        return "timerfd_settime";
#endif

#ifdef SYS_times
    case SYS_times:
        return "times";
#endif

#ifdef SYS_tkill
    case SYS_tkill:
        return "tkill";
#endif

#ifdef SYS_truncate
    case SYS_truncate:
        return "truncate";
#endif

#ifdef SYS_umask
    case SYS_umask:
        return "umask";
#endif

#ifdef SYS_umount2
    case SYS_umount2:
        return "umount2";
#endif

#ifdef SYS_uname
    case SYS_uname:
        return "uname";
#endif

#ifdef SYS_unlink
    case SYS_unlink:
        return "unlink";
#endif

#ifdef SYS_unlinkat
    case SYS_unlinkat:
        return "unlinkat";
#endif

#ifdef SYS_unshare
    case SYS_unshare:
        return "unshare";
#endif

#ifdef SYS_uselib
    case SYS_uselib:
        return "uselib";
#endif

#ifdef SYS_ustat
    case SYS_ustat:
        return "ustat";
#endif

#ifdef SYS_utime
    case SYS_utime:
        return "utime";
#endif

#ifdef SYS_utimensat
    case SYS_utimensat:
        return "utimensat";
#endif

#ifdef SYS_utimes
    case SYS_utimes:
        return "utimes";
#endif

#ifdef SYS_vfork
    case SYS_vfork:
        return "vfork";
#endif

#ifdef SYS_vhangup
    case SYS_vhangup:
        return "vhangup";
#endif

#ifdef SYS_vmsplice
    case SYS_vmsplice:
        return "vmsplice";
#endif

#ifdef SYS_vserver
    case SYS_vserver:
        return "vserver";
#endif

#ifdef SYS_wait4
    case SYS_wait4:
        return "wait4";
#endif

#ifdef SYS_waitid
    case SYS_waitid:
        return "waitid";
#endif

#ifdef SYS_write
    case SYS_write:
        return "write";
#endif

#ifdef SYS_writev
    case SYS_writev:
        return "writev";
#endif

#ifdef SYS_accept
    case SYS_accept:
        return "accept";
#endif

#ifdef SYS_arch_prctl
    case SYS_arch_prctl:
        return "arch_prctl";
#endif

#ifdef SYS_bind
    case SYS_bind:
        return "bind";
#endif

#ifdef SYS_connect
    case SYS_connect:
        return "connect";
#endif

#ifdef SYS_epoll_ctl_old
    case SYS_epoll_ctl_old:
        return "epoll_ctl_old";
#endif

#ifdef SYS_epoll_wait_old
    case SYS_epoll_wait_old:
        return "epoll_wait_old";
#endif

#ifdef SYS_getpeername
    case SYS_getpeername:
        return "getpeername";
#endif

#ifdef SYS_getsockname
    case SYS_getsockname:
        return "getsockname";
#endif

#ifdef SYS_getsockopt
    case SYS_getsockopt:
        return "getsockopt";
#endif

#ifdef SYS_listen
    case SYS_listen:
        return "listen";
#endif

#ifdef SYS_msgctl
    case SYS_msgctl:
        return "msgctl";
#endif

#ifdef SYS_msgget
    case SYS_msgget:
        return "msgget";
#endif

#ifdef SYS_msgrcv
    case SYS_msgrcv:
        return "msgrcv";
#endif

#ifdef SYS_msgsnd
    case SYS_msgsnd:
        return "msgsnd";
#endif

#ifdef SYS_newfstatat
    case SYS_newfstatat:
        return "newfstatat";
#endif

#ifdef SYS_recvfrom
    case SYS_recvfrom:
        return "recvfrom";
#endif

#ifdef SYS_recvmsg
    case SYS_recvmsg:
        return "recvmsg";
#endif

#ifdef SYS_security
    case SYS_security:
        return "security";
#endif

#ifdef SYS_semctl
    case SYS_semctl:
        return "semctl";
#endif

#ifdef SYS_semget
    case SYS_semget:
        return "semget";
#endif

#ifdef SYS_semop
    case SYS_semop:
        return "semop";
#endif

#ifdef SYS_semtimedop
    case SYS_semtimedop:
        return "semtimedop";
#endif

#ifdef SYS_sendmsg
    case SYS_sendmsg:
        return "sendmsg";
#endif

#ifdef SYS_sendto
    case SYS_sendto:
        return "sendto";
#endif

#ifdef SYS_setsockopt
    case SYS_setsockopt:
        return "setsockopt";
#endif

#ifdef SYS_shmat
    case SYS_shmat:
        return "shmat";
#endif

#ifdef SYS_shmctl
    case SYS_shmctl:
        return "shmctl";
#endif

#ifdef SYS_shmdt
    case SYS_shmdt:
        return "shmdt";
#endif

#ifdef SYS_shmget
    case SYS_shmget:
        return "shmget";
#endif

#ifdef SYS_shutdown
    case SYS_shutdown:
        return "shutdown";
#endif

#ifdef SYS_socket
    case SYS_socket:
        return "socket";
#endif

#ifdef SYS_socketpair
    case SYS_socketpair:
        return "socketpair";
#endif

#ifdef SYS_tuxcall
    case SYS_tuxcall:
        return "tuxcall";
#endif

#ifdef SYS__llseek
    case SYS__llseek:
        return "_llseek";
#endif

#ifdef SYS__newselect
    case SYS__newselect:
        return "_newselect";
#endif

#ifdef SYS_bdflush
    case SYS_bdflush:
        return "bdflush";
#endif

#ifdef SYS_break
    case SYS_break:
        return "break";
#endif

#ifdef SYS_chown32
    case SYS_chown32:
        return "chown32";
#endif

#ifdef SYS_fadvise64_64
    case SYS_fadvise64_64:
        return "fadvise64_64";
#endif

#ifdef SYS_fchown32
    case SYS_fchown32:
        return "fchown32";
#endif

#ifdef SYS_fcntl64
    case SYS_fcntl64:
        return "fcntl64";
#endif

#ifdef SYS_fstat64
    case SYS_fstat64:
        return "fstat64";
#endif

#ifdef SYS_fstatat64
    case SYS_fstatat64:
        return "fstatat64";
#endif

#ifdef SYS_fstatfs64
    case SYS_fstatfs64:
        return "fstatfs64";
#endif

#ifdef SYS_ftime
    case SYS_ftime:
        return "ftime";
#endif

#ifdef SYS_ftruncate64
    case SYS_ftruncate64:
        return "ftruncate64";
#endif

#ifdef SYS_getcpu
    case SYS_getcpu:
        return "getcpu";
#endif

#ifdef SYS_getegid32
    case SYS_getegid32:
        return "getegid32";
#endif

#ifdef SYS_geteuid32
    case SYS_geteuid32:
        return "geteuid32";
#endif

#ifdef SYS_getgid32
    case SYS_getgid32:
        return "getgid32";
#endif

#ifdef SYS_getgroups32
    case SYS_getgroups32:
        return "getgroups32";
#endif

#ifdef SYS_getresgid32
    case SYS_getresgid32:
        return "getresgid32";
#endif

#ifdef SYS_getresuid32
    case SYS_getresuid32:
        return "getresuid32";
#endif

#ifdef SYS_getuid32
    case SYS_getuid32:
        return "getuid32";
#endif

#ifdef SYS_gtty
    case SYS_gtty:
        return "gtty";
#endif

#ifdef SYS_idle
    case SYS_idle:
        return "idle";
#endif

#ifdef SYS_ipc
    case SYS_ipc:
        return "ipc";
#endif

#ifdef SYS_lchown32
    case SYS_lchown32:
        return "lchown32";
#endif

#ifdef SYS_lock
    case SYS_lock:
        return "lock";
#endif

#ifdef SYS_lstat64
    case SYS_lstat64:
        return "lstat64";
#endif

#ifdef SYS_madvise1
    case SYS_madvise1:
        return "madvise1";
#endif

#ifdef SYS_mmap2
    case SYS_mmap2:
        return "mmap2";
#endif

#ifdef SYS_mpx
    case SYS_mpx:
        return "mpx";
#endif

#ifdef SYS_nice
    case SYS_nice:
        return "nice";
#endif

#ifdef SYS_oldfstat
    case SYS_oldfstat:
        return "oldfstat";
#endif

#ifdef SYS_oldlstat
    case SYS_oldlstat:
        return "oldlstat";
#endif

#ifdef SYS_oldolduname
    case SYS_oldolduname:
        return "oldolduname";
#endif

#ifdef SYS_oldstat
    case SYS_oldstat:
        return "oldstat";
#endif

#ifdef SYS_olduname
    case SYS_olduname:
        return "olduname";
#endif

#ifdef SYS_prof
    case SYS_prof:
        return "prof";
#endif

#ifdef SYS_profil
    case SYS_profil:
        return "profil";
#endif

#ifdef SYS_readdir
    case SYS_readdir:
        return "readdir";
#endif

#ifdef SYS_sendfile64
    case SYS_sendfile64:
        return "sendfile64";
#endif

#ifdef SYS_setfsgid32
    case SYS_setfsgid32:
        return "setfsgid32";
#endif

#ifdef SYS_setfsuid32
    case SYS_setfsuid32:
        return "setfsuid32";
#endif

#ifdef SYS_setgid32
    case SYS_setgid32:
        return "setgid32";
#endif

#ifdef SYS_setgroups32
    case SYS_setgroups32:
        return "setgroups32";
#endif

#ifdef SYS_setregid32
    case SYS_setregid32:
        return "setregid32";
#endif

#ifdef SYS_setresgid32
    case SYS_setresgid32:
        return "setresgid32";
#endif

#ifdef SYS_setresuid32
    case SYS_setresuid32:
        return "setresuid32";
#endif

#ifdef SYS_setreuid32
    case SYS_setreuid32:
        return "setreuid32";
#endif

#ifdef SYS_setuid32
    case SYS_setuid32:
        return "setuid32";
#endif

#ifdef SYS_sgetmask
    case SYS_sgetmask:
        return "sgetmask";
#endif

#ifdef SYS_sigaction
    case SYS_sigaction:
        return "sigaction";
#endif

#ifdef SYS_signal
    case SYS_signal:
        return "signal";
#endif

#ifdef SYS_sigpending
    case SYS_sigpending:
        return "sigpending";
#endif

#ifdef SYS_sigprocmask
    case SYS_sigprocmask:
        return "sigprocmask";
#endif

#ifdef SYS_sigreturn
    case SYS_sigreturn:
        return "sigreturn";
#endif

#ifdef SYS_sigsuspend
    case SYS_sigsuspend:
        return "sigsuspend";
#endif

#ifdef SYS_socketcall
    case SYS_socketcall:
        return "socketcall";
#endif

#ifdef SYS_ssetmask
    case SYS_ssetmask:
        return "ssetmask";
#endif

#ifdef SYS_stat64
    case SYS_stat64:
        return "stat64";
#endif

#ifdef SYS_statfs64
    case SYS_statfs64:
        return "statfs64";
#endif

#ifdef SYS_stime
    case SYS_stime:
        return "stime";
#endif

#ifdef SYS_stty
    case SYS_stty:
        return "stty";
#endif

#ifdef SYS_truncate64
    case SYS_truncate64:
        return "truncate64";
#endif

#ifdef SYS_ugetrlimit
    case SYS_ugetrlimit:
        return "ugetrlimit";
#endif

#ifdef SYS_ulimit
    case SYS_ulimit:
        return "ulimit";
#endif

#ifdef SYS_umount
    case SYS_umount:
        return "umount";
#endif

#ifdef SYS_vm86
    case SYS_vm86:
        return "vm86";
#endif

#ifdef SYS_vm86old
    case SYS_vm86old:
        return "vm86old";
#endif

#ifdef SYS_waitpid
    case SYS_waitpid:
        return "waitpid";
#endif

    default:
        return "unknown";
    }
}
