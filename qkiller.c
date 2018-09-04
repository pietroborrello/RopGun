#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h> /* for pid_t */
#include <sys/wait.h>  /* for wait */
#include <linux/perf_event.h>
#include <asm/unistd.h>

struct read_format
{
    uint64_t nr;
    struct
    {
        uint64_t value;
        uint64_t id;
    } values[];
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

int main(int argc, char **argv)
{
    struct perf_event_attr pe;
    int fd1, fd2;
    int ret;
    uint64_t id1, id2;
    uint64_t val1, val2;
    int i;
    char buf[4096];
    struct read_format *rf = (struct read_format *)buf;

    /*Spawn a child to run the program.*/
    pid_t pid = fork();
    if (pid == 0)
    { /* child process */
        static char *_argv[] = {NULL};

        sleep(2); // TODO: FIXIT!!

        execv("./run.sh", _argv);
        exit(127); /* only if execv fails */
    }
    else
    { /* pid!=0; parent process */

        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(struct perf_event_attr);
        pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
        pe.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
        pe.disabled = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;
        fd1 = perf_event_open(&pe, pid, -1, -1, 0);
        if (fd1 == -1)
        {
            fprintf(stderr, "Error opening leader %llx\n", pe.config);
            exit(EXIT_FAILURE);
        }
        ioctl(fd1, PERF_EVENT_IOC_ID, &id1);

        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(struct perf_event_attr);
        pe.config = PERF_COUNT_HW_BRANCH_MISSES;
        pe.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
        pe.disabled = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;
        
        fd2 = perf_event_open(&pe, pid, -1, fd, 0);
        if (fd2 == -1)
        {
            fprintf(stderr, "Error opening second event %llx\n", pe.config);
            exit(EXIT_FAILURE);
        }
        ioctl(fd2, PERF_EVENT_IOC_ID, &id2);

        ioctl(fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

        waitpid(pid, 0, 0); /* wait for child to exit */

        ioctl(fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
        ret = read(fd1, buf, sizeof(buf));
        if (ret == -1)
        {
            fprintf(stderr, "Error reading events: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }
        for (i = 0; i < rf->nr; i++) {
            if (rf->values[i].id == id1) {
                val1 = rf->values[i].value;
            } else if (rf->values[i].id == id2) {
                val2 = rf->values[i].value;
            }
        }

        printf("%lld events read:\n", rf->nr);
        printf("%lld branches\n", val1);
        printf("%lld mispredicted branches\n", val2);

        close(fd);
    }
   
}
