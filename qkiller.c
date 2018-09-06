#include "qkiller.h"

#define RETIRED_BRANCES 0x88
#define MISPREDICTED_BRANCES 0x89
#define RET_MASK 0x88

#define RET_THRESHOLD 20
#define WARN_THRESHOLD 60.0

#define MONITOR_MODE 0
#define KILL_MODE 1

const char *callname(long call);
const char *callname32(long call);

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

int trace_child(pid_t child, int mode)
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
        if(mode == MONITOR_MODE)
        {
            union {
                struct user_regs_struct x86_64_r;
                struct i386_user_regs_struct i386_r;
            } regs;
            struct iovec x86_io = {
                .iov_base = &regs,
                .iov_len = sizeof(regs)
            };
            //ptrace(PTRACE_GETREGS, child, NULL, &regs);
            ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &x86_io);
            if (x86_io.iov_len == sizeof(struct i386_user_regs_struct)) {
                // this is a 32-bit process
                fprintf(stderr, ANSI_COLOR_BLUE "%s()" ANSI_COLOR_RESET "\n", callname32(regs.i386_r.orig_eax));
            } else {
                fprintf(stderr, ANSI_COLOR_CYAN "%s()" ANSI_COLOR_RESET "\n", callname(regs.x86_64_r.orig_rax));
            }
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

        if(mode == MONITOR_MODE)
        {
            //printf("%lu events read:\n", rf->nr);
            // Taken speculative and retired indirect branches that are returns.
            printf("%'lu returns\n", retired_rets);
            // Taken speculative and retired mispredicted indirect branches that are returns.
            printf("%'lu mispredicted returns\n", mispredicted_rets);
        }

        if (retired_rets > RET_THRESHOLD)
        {
            misprediction_rate = (((double) mispredicted_rets) / retired_rets) * 100;

            if (mode == MONITOR_MODE) 
            {
                if (misprediction_rate > WARN_THRESHOLD)
                    printf(ANSI_COLOR_RED "%.1lf%% misprediction" ANSI_COLOR_RESET "\n", misprediction_rate);
                else
                    printf(ANSI_COLOR_GREEN "%.1lf%% misprediction" ANSI_COLOR_RESET "\n", misprediction_rate);
            }
            else if (mode == KILL_MODE)
            {
                if (misprediction_rate > WARN_THRESHOLD)
                    printf(ANSI_COLOR_RED "AAAAAAAAAAAAAH" ANSI_COLOR_RESET "\n", misprediction_rate);
            }
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

void print_help(char* name)
{
    fprintf(stderr, "Usage: %s <-m|-k> <cmd>\n", name);
    fprintf(stderr, "-m\tmonitor mode\n");
    fprintf(stderr, "-k\tkiller mode\n");
    return;
}

int main(int argc, char **argv)
{
    int mode = 0;

    if (argc < 3)
    {
        print_help(argv[0]);
        exit(EXIT_FAILURE);
	}
    if (argv[1][0] == '-')
    {
        switch (argv[1][1])
        {
        case 'm':
            mode = MONITOR_MODE;
            break;
        case 'k':
            mode = KILL_MODE;
            break;
        default:
            print_help(argv[0]);
            exit(EXIT_FAILURE);
    } else {
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    /*Spawn a child to run the program.*/
    pid_t pid = fork();
    if (pid == 0)
    { /* child process */
        extern char **environ;
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);
        execve(argv[2], &argv[2], environ);
        fprintf(stderr, "Execv failed: %s\n", strerror(errno));
        exit(127); /* only if execv fails */
    }
    else
    { /* pid!=0; parent process */
        return trace_child(pid, mode);
    }
}
