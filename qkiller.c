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

struct events_t
{
    unsigned long long nr;           /* The number of events */
    unsigned long long value1; /* The value of the event */
    unsigned long long value2;
    unsigned long long value3;
    unsigned long long value4;
    unsigned long long value5;
    unsigned long long value6;
    unsigned long long value7;
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
    struct events_t events;
    int fd;
    int ret;

    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_BRANCH_INSTRUCTIONS;
    pe.read_format = PERF_FORMAT_GROUP;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

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
        fd = perf_event_open(&pe, pid, -1, -1, 0);
        if (fd == -1)
        {
            fprintf(stderr, "Error opening leader %llx\n", pe.config);
            exit(EXIT_FAILURE);
        }
        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(struct perf_event_attr);
        pe.config = PERF_COUNT_HW_BRANCH_MISSES;
        pe.read_format = PERF_FORMAT_GROUP;
        pe.disabled = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;
        
        ret = perf_event_open(&pe, pid, -1, fd, 0);
        if (ret == -1)
        {
            fprintf(stderr, "Error opening second event %llx\n", pe.config);
            exit(EXIT_FAILURE);
        }

        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

        waitpid(pid, 0, 0); /* wait for child to exit */

        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        ret = read(fd, &events, sizeof(struct events_t));
        if (ret == -1)
        {
            fprintf(stderr, "Error reading events: %s\n",strerror(errno));
            exit(EXIT_FAILURE);
        }

        printf("%lld events read:\n", events.nr);
        printf("%lld branches\n", events.value1);
        printf("%lld mispredicted branches\n", events.value2);
        printf("%lld mispredicted branches\n", events.value3);
        printf("%lld mispredicted branches\n", events.value4);
        printf("%lld mispredicted branches\n", events.value5);

        close(fd);
    }
   
}
