#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/types.h> /* for pid_t */
#include <sys/wait.h>  /* for wait */
#include <linux/perf_event.h>
#include <asm/unistd.h>

#define SEM_NAME "qkiller_start_semaphore"

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

int main(int argc, char**argv)
{
    struct perf_event_attr pe;
    int fd1, fd2;
    int ret;
    uint64_t id1, id2;
    uint64_t val1, val2;
    int i;
    char buf[4096];
    struct read_format *rf = (struct read_format *)buf;
    sem_t *sem;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <cmd>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

    if ((sem = sem_open(SEM_NAME, O_CREAT | O_EXCL)) == SEM_FAILED)
    {
        perror("semaphore initilization");
        exit(1);
    }

    /*Spawn a child to run the program.*/
    pid_t pid = fork();
    if (pid == 0)
    { /* child process */
        extern char **environ;
        sem_wait(sem);

        execve(argv[1], &argv[1], environ);
        fprintf(stderr, "Execv failed: %s\n", strerror(errno));
        exit(127); /* only if execv fails */
    }
    else
    { /* pid!=0; parent process */

        fd1 = init_event_listener(&pe, PERF_TYPE_RAW, 0x8888, pid, -1);
        if (fd1 == -1)
        {
            fprintf(stderr, "Error opening leader %llx\n", pe.config);
            ret = EXIT_FAILURE;
            goto out;
        }
        ioctl(fd1, PERF_EVENT_IOC_ID, &id1);

        fd2 = init_event_listener(&pe, PERF_TYPE_RAW, 0x8889, pid, fd1);
        if (fd2 == -1)
        {
            fprintf(stderr, "Error opening second event %llx\n", pe.config);
            ret = EXIT_FAILURE;
            goto out;
        }
        ioctl(fd2, PERF_EVENT_IOC_ID, &id2);

        ioctl(fd1, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
        ioctl(fd1, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
        
        sem_post(sem);
        waitpid(pid, 0, 0); /* wait for child to exit */

        ioctl(fd1, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
        ret = read(fd1, buf, sizeof(buf));
        if (ret == -1)
        {
            fprintf(stderr, "Error reading events: %s\n",strerror(errno));
            ret = EXIT_FAILURE;
            goto out;
        }
        for (i = 0; i < rf->nr; i++) {
            if (rf->values[i].id == id1) {
                val1 = rf->values[i].value;
            } else if (rf->values[i].id == id2) {
                val2 = rf->values[i].value;
            }
        }
        // format numbers to 1.000.000 like
        setlocale(LC_NUMERIC, "");
        printf("%lu events read:\n", rf->nr);
        printf("%'lu retired returns\n", val1);
        printf("%'lu mispredicted retired returns\n", val2);
out:    
        sem_close(sem);
        sem_unlink(SEM_NAME);
        close(fd2);
        close(fd1);
        return ret;
    }
}
