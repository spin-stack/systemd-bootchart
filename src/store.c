/***
  This file is part of systemd.

  Copyright (C) 2009-2013 Intel Corporation

  Authors:
    Auke Kok <auke-jan.h.kok@intel.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
 ***/

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bootchart.h"
#include "def.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "log.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "store.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "time-util.h"

/*
 * Alloc a static 4k buffer for stdio - primarily used to increase
 * PSS buffering from the default 1k stdin buffer to reduce
 * read() overhead.
 */
static char smaps_buf[4096];

double gettime_ns(void) {
        struct timespec n;

        clock_gettime(clock_boottime_or_monotonic(), &n);

        return (n.tv_sec + (n.tv_nsec / (double) NSEC_PER_SEC));
}

static char *bufgetline(char *buf) {
        char *c;

        if (!buf)
                return NULL;

        c = strchr(buf, '\n');
        if (c)
                c++;

        return c;
}

static int pid_cmdline_strscpy(int procfd, char *buffer, size_t buf_len, int pid) {
        char filename[PATH_MAX];
        _cleanup_close_ int fd = -1;
        ssize_t n;

        sprintf(filename, "%d/cmdline", pid);
        fd = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        n = read(fd, buffer, buf_len-1);
        if (n > 0) {
                int i;
                for (i = 0; i < n; i++)
                        if (buffer[i] == '\0')
                                buffer[i] = ' ';
                buffer[n] = '\0';
        }

        return 0;
}

/* Reads the file NAME in the process's directory, NUL-terminated, and returns its length. */
static ssize_t pid_read(int procfd, int pid, const char *name, char *buf, size_t size) {
        char path[64];
        _cleanup_close_ int fd = -1;
        ssize_t n;

        xsprintf(path, "%d/%s", pid, name);
        fd = openat(procfd, path, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        n = read(fd, buf, size - 1);
        if (n < 0)
                return -errno;

        buf[n] = '\0';
        return n;
}

/* The process's cgroup: systemd's own "name=systemd" hierarchy's path on a v1 or hybrid
 * hierarchy, and otherwise the cgroup v2 path, from the "0::" line of /proc/PID/cgroup. */
static char *pid_cgroup(int procfd, int pid) {
        char buf[4096];
        char *line, *v2 = NULL;

        if (pid_read(procfd, pid, "cgroup", buf, sizeof(buf)) <= 0)
                return NULL;

        for (line = buf; line && *line; line = bufgetline(line)) {
                char *p = strstr(line, ":name=systemd:");

                if (p && p < strchrnul(line, '\n')) {
                        p += strlen(":name=systemd:");
                        return strndup(p, strcspn(p, "\n"));
                }

                if (startswith(line, "0::"))
                        v2 = line + 3;
        }

        return v2 ? strndup(v2, strcspn(v2, "\n")) : NULL;
}

/* Reads what names the process: its comm, its command line with --cmdline, and its cgroup with
 * --control-group. All three change while a process lives, and in a boot they change early:
 * systemd's executor is exec'd through a file descriptor, so the kernel names it after the
 * descriptor ("9") until it execs the service, and the service's cgroup is the init.scope it
 * was forked in until it moves itself into its unit's. So they are read again on every sample
 * in which the process ran, which is when an exec or a move can have happened. */
static void pid_read_identity(int procfd, struct ps_struct *ps) {
        char comm[64];

        if (pid_read(procfd, ps->pid, "comm", comm, sizeof(comm)) > 0)
                strscpy(ps->name, sizeof(ps->name), truncate_nl(comm));

        if (arg_show_cmdline)
                pid_cmdline_strscpy(procfd, ps->name, sizeof(ps->name), ps->pid);

        if (arg_show_cgroup) {
                char *cgroup = pid_cgroup(procfd, ps->pid);

                if (cgroup) {
                        free(ps->cgroup);
                        ps->cgroup = cgroup;
                }
        }
}

/* The process's read_bytes and write_bytes from /proc/PID/io, which a kernel without
 * CONFIG_TASK_IO_ACCOUNTING does not have; the sample keeps the last values then. */
static void pid_read_io(int procfd, int pid, struct ps_sched_struct *sample) {
        char buf[512];
        char *line;

        if (pid_read(procfd, pid, "io", buf, sizeof(buf)) <= 0)
                return;

        for (line = buf; line && *line; line = bufgetline(line)) {
                const char *v;

                if ((v = startswith(line, "read_bytes: ")))
                        sample->read_bytes = strtoull(v, NULL, 10);
                else if ((v = startswith(line, "write_bytes: ")))
                        sample->write_bytes = strtoull(v, NULL, 10);
        }
}

const char *ps_unit(const struct ps_struct *ps) {
        const char *p, *slash;

        if (!ps->cgroup)
                return NULL;

        /* The slices above a unit say where it was placed, not what it is:
         * /system.slice/systemd-journald.service is systemd-journald.service, and
         * /user.slice/user-0.slice/user@0.service/init.scope is user@0.service/init.scope. */
        p = ps->cgroup;
        while (*p == '/')
                p++;
        while ((slash = strchr(p, '/'))) {
                if (slash - p < 6 || strncmp(slash - 6, ".slice", 6) != 0)
                        break;
                p = slash + 1;
        }

        return *p ? p : ps->cgroup;
}

static void garbage_collect_dead_processes(struct ps_struct *ps_first) {
        struct ps_struct *ps;
        struct ps_struct *ps_next;

        ps = ps_first;
        while ((ps_next = ps->next_running)) {
                if (!ps_next->still_running) {
                        /* close the stream and fds */
                        ps_next->schedstat = safe_close(ps_next->schedstat);
                        if (ps_next->smaps) {
                                fclose(ps_next->smaps);
                                ps_next->smaps = NULL;
                        }

                        ps->next_running = ps_next->next_running;
                } else {
                        ps = ps_next;
                }
                /* this resets the flag for both running and dead processes*/
                ps_next->still_running = false;
        }
}


static const char *const pressure_files[_PRESSURE_MAX] = {
        [PRESSURE_CPU] = "pressure/cpu",
        [PRESSURE_IO] = "pressure/io",
        [PRESSURE_MEMORY] = "pressure/memory",
};

/* The stall totals in /proc/pressure: microseconds in which some task, or every task ("full"),
 * waited for the resource. A kernel without CONFIG_PSI, or booted with psi=0, has none and the
 * totals stay zero. */
static void read_pressure(int procfd, struct list_sample_data *sampledata) {
        static int fds[_PRESSURE_MAX] = { -1, -1, -1 };
        int i;

        for (i = 0; i < _PRESSURE_MAX; i++) {
                char buf[256];
                char *line;
                ssize_t n;

                if (fds[i] < 0) {
                        fds[i] = openat(procfd, pressure_files[i], O_RDONLY|O_CLOEXEC);
                        if (fds[i] < 0)
                                continue;
                }

                n = pread(fds[i], buf, sizeof(buf) - 1, 0);
                if (n <= 0)
                        continue;
                buf[n] = '\0';

                for (line = buf; line && *line; line = bufgetline(line)) {
                        const char *total = strstr(line, "total=");
                        int which;

                        if (!total)
                                continue;
                        if (startswith(line, "some "))
                                which = PRESSURE_SOME;
                        else if (startswith(line, "full "))
                                which = PRESSURE_FULL;
                        else
                                continue;
                        sampledata->pressure[i][which] = strtoull(total + strlen("total="), NULL, 10);
                }
        }
}

static int pid_compare(const void *a, const void *b) {
        int x = *(const int *) a, y = *(const int *) b;

        return (x > y) - (x < y);
}

/* The pids in the proc directory, ascending. The process tree is built in the order processes
 * are first seen and needs a parent seen before the processes it forked, which /proc's own order
 * gives and a directory standing in for it with --proc need not. */
static int read_pids(DIR *proc, int **pids, size_t *allocated) {
        struct dirent *ent;
        int n = 0;

        while ((ent = readdir(proc)) != NULL) {
                int pid;

                if ((ent->d_name[0] < '0') || (ent->d_name[0] > '9'))
                        continue;

                pid = atoi(ent->d_name);
                if (pid >= MAXPIDS)
                        continue;

                if (!GREEDY_REALLOC(*pids, *allocated, n + 1))
                        return log_oom();
                (*pids)[n++] = pid;
        }

        qsort(*pids, n, sizeof(int), pid_compare);
        return n;
}

int log_sample(DIR *proc,
               int sample,
               struct ps_struct *ps_first,
               struct list_sample_data **ptr,
               int *pscount,
               int *cpus) {

        static int vmstat = -1;
        _cleanup_free_ char *buf_schedstat = NULL;
        _cleanup_fclose_ FILE *f_schedstat = NULL;
        char buf[4096];
        char key[256];
        char val[256];
        char rt[256];
        char wt[256];
        char *m;
        int r;
        int c;
        int p;
        static int e_fd = -1;
        ssize_t s;
        ssize_t n;
        struct dirent *ent;
        int fd;
        struct list_sample_data *sampledata;
        struct ps_sched_struct *ps_prev = NULL;
        int procfd;
        int taskfd = -1;
        static int *pids = NULL;
        static size_t pids_allocated = 0;
        int n_pids, i;

        sampledata = *ptr;

        procfd = dirfd(proc);
        if (procfd < 0)
                return -errno;

        if (vmstat < 0) {
                /* block stuff */
                vmstat = openat(procfd, "vmstat", O_RDONLY|O_CLOEXEC);
                if (vmstat < 0)
                        return log_error_errno(errno, "Failed to open /proc/vmstat: %m");
        }

        n = pread(vmstat, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
                vmstat = safe_close(vmstat);
                if (n < 0)
                        return -errno;
                return -ENODATA;
        }

        buf[n] = '\0';

        m = buf;
        while (m) {
                if (sscanf(m, "%s %s", key, val) < 2)
                        goto vmstat_next;
                if (streq(key, "pgpgin"))
                        sampledata->blockstat.bi = atoi(val);
                if (streq(key, "pgpgout")) {
                        sampledata->blockstat.bo = atoi(val);
                        break;
                }
vmstat_next:
                m = bufgetline(m);
                if (!m)
                        break;
        }

        /* Parse "/proc/schedstat" for overall CPU utilization */
        fd = openat(procfd, "schedstat", O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Unable to open schedstat: %m");
        f_schedstat = fdopen(fd, "re");
        if (!f_schedstat) {
                safe_close(fd);
                return log_error_errno(errno, "Unable to open schedstat: %m");
        }
        r = read_full_stream(f_schedstat, &buf_schedstat, NULL);
        if (r < 0)
                return log_error_errno(r, "Unable to read schedstat: %m");

        m = buf_schedstat;
        while (m) {
                if (sscanf(m, "%s %*s %*s %*s %*s %*s %*s %s %s", key, rt, wt) < 3)
                        goto schedstat_next;

                if (strstr(key, "cpu")) {
                        r = safe_atoi((const char*)(key+3), &c);
                        if (r < 0 || c > MAXCPUS -1)
                                /* Oops, we only have room for MAXCPUS data */
                                break;
                        sampledata->runtime[c] = atoll(rt);
                        sampledata->waittime[c] = atoll(wt);

                        if (c == *cpus)
                                *cpus = c + 1;
                }
schedstat_next:
                m = bufgetline(m);
                if (!m)
                        break;
        }

        read_pressure(procfd, sampledata);

        if (arg_entropy) {
                if (e_fd < 0) {
                        e_fd = openat(procfd, "sys/kernel/random/entropy_avail", O_RDONLY|O_CLOEXEC);
                        if (e_fd < 0)
                                return log_error_errno(errno, "Failed to open /proc/sys/kernel/random/entropy_avail: %m");
                }

                n = pread(e_fd, buf, sizeof(buf) - 1, 0);
                if (n <= 0) {
                        e_fd = safe_close(e_fd);
                } else {
                        buf[n] = '\0';
                        sampledata->entropy_avail = atoi(buf);
                }
        }

        r = read_pids(proc, &pids, &pids_allocated);
        if (r < 0)
                return r;
        n_pids = r;

        for (i = 0; i < n_pids; i++) {
                char filename[PATH_MAX];
                int pid = pids[i];
                struct ps_struct *ps;
                struct stat task_st;

                ps = ps_first;
                while (ps->next_running) {
                        ps = ps->next_running;
                        if (ps->pid == pid)
                                break;
                }

                /* end of our LL? then append a new record */
                if (ps->pid != pid) {
                        struct ps_struct *parent;

                        /* find the insertion point for the last item */
                        struct ps_struct **ps_next = &ps->next_ps;
                        while (*ps_next) {
                                ps_next = &(*ps_next)->next_ps;
                        }

                        assert(!*ps_next);
                        assert(!ps->next_running);
                        *ps_next = ps->next_running = new0(struct ps_struct, 1);
                        if (!*ps_next)
                                return log_oom();

                        ps = *ps_next;
                        ps->pid = pid;
                        ps->schedstat = -1;

                        ps->sample = new0(struct ps_sched_struct, 1);
                        if (!ps->sample)
                                return log_oom();

                        ps->sample->sampledata = sampledata;

                        (*pscount)++;

                        /* mark our first sample */
                        ps->first = ps->last = ps->sample;

                        /* ppid, after the comm in parentheses, which can hold spaces and
                         * parentheses of its own, so after the last ')' */
                        if (pid_read(procfd, pid, "stat", buf, sizeof(buf)) <= 0)
                                continue;

                        m = strrchr(buf, ')');
                        if (!m || sscanf(m + 1, " %*c %i", &p) != 1)
                                continue;

                        ps->ppid = p;

                        /*
                         * setup child pointers
                         *
                         * these are used to paint the tree coherently later
                         * each parent has a LL of children, and a LL of siblings
                         */
                        if (pid != 1) {
                                /* nothing to do for init atm */

                                /* kthreadd has ppid=0, which breaks our tree ordering */
                                if (ps->ppid == 0)
                                        ps->ppid = 1;

                                parent = ps_first;
                                while ((parent->next_ps && parent->pid != ps->ppid))
                                        parent = parent->next_ps;

                                if (parent->pid != ps->ppid) {
                                        /* orphan */
                                        ps->ppid = 1;
                                        parent = ps_first->next_ps;
                                }

                                ps->parent = parent;

                                /*
                                 * append ourselves to the list of children
                                 * TODO: consider if prepending is OK for efficiency here.
                                 */
                                {
                                        struct ps_struct **children = &parent->children;
                                        while (*children)
                                                children = &(*children)->next;
                                        *children = ps;
                                }
                        }
                }
                /* else -> found pid, append data in ps */

                /* below here is all continuous logging parts - we get here on every
                 * iteration */

                /* rt, wt */
                if (ps->schedstat < 0) {
                        sprintf(filename, "%d/schedstat", pid);
                        ps->schedstat = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                        if (ps->schedstat < 0)
                                continue;
                }

                s = pread(ps->schedstat, buf, sizeof(buf) - 1, 0);
                if (s <= 0)
                        continue;

                buf[s] = '\0';

                if (!sscanf(buf, "%s %s %*s", rt, wt))
                        continue;

                ps->sample->next = new0(struct ps_sched_struct, 1);
                if (!ps->sample->next)
                        return log_oom();

                ps->sample->next->prev = ps->sample;
                ps->sample = ps->sample->next;
                ps->last = ps->sample;
                ps->sample->runtime = atoll(rt);
                ps->sample->waittime = atoll(wt);
                ps->sample->sampledata = sampledata;
                ps->sample->ps_new = ps;
                if (ps_prev)
                        ps_prev->cross = ps->sample;

                ps_prev = ps->sample;

                /* Take into account CPU runtime/waittime spent in non-main threads of the process
                 * by parsing "/proc/[pid]/task/[tid]/schedstat" for all [tid] != [pid]
                 * See https://github.com/systemd/systemd/issues/139
                 */

                /* Browse directory "/proc/[pid]/task" to know the thread ids of process [pid],
                 * when it has threads: procfs counts them in the directory's link count, two
                 * and one a thread. Most of a boot's processes have one, and listing their task
                 * directories took most of the sampler's time. */
                snprintf(filename, sizeof(filename), PID_FMT "/task", pid);
                if (fstatat(procfd, filename, &task_st, 0) < 0 || task_st.st_nlink <= 3)
                        taskfd = -1;
                else
                        taskfd = openat(procfd, filename, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                if (taskfd >= 0) {
                        _cleanup_closedir_ DIR *taskdir = NULL;

                        taskdir = fdopendir(taskfd);
                        if (!taskdir) {
                                safe_close(taskfd);
                                return -errno;
                        }
                        FOREACH_DIRENT(ent, taskdir, break) {
                                int tid = -1;
                                _cleanup_close_ int tid_schedstat = -1;
                                long long delta_rt;
                                long long delta_wt;

                                if ((ent->d_name[0] < '0') || (ent->d_name[0] > '9'))
                                        continue;

                                /* Skip main thread as it was already accounted */
                                r = safe_atoi(ent->d_name, &tid);
                                if (r < 0 || tid == pid)
                                        continue;

                                /* Parse "/proc/[pid]/task/[tid]/schedstat" */
                                snprintf(filename, sizeof(filename), PID_FMT "/schedstat", tid);
                                tid_schedstat = openat(taskfd, filename, O_RDONLY|O_CLOEXEC);

                                if (tid_schedstat == -1)
                                        continue;

                                s = pread(tid_schedstat, buf, sizeof(buf) - 1, 0);
                                if (s <= 0)
                                        continue;
                                buf[s] = '\0';

                                if (!sscanf(buf, "%s %s %*s", rt, wt))
                                        continue;

                                r = safe_atolli(rt, &delta_rt);
                                if (r < 0)
                                    continue;
                                r = safe_atolli(wt, &delta_wt);
                                if (r < 0)
                                    continue;
                                ps->sample->runtime  += delta_rt;
                                ps->sample->waittime += delta_wt;
                        }
                }

                /* after its threads', which the main thread's schedstat leaves out */
                ps->total = (ps->last->runtime - ps->first->runtime)
                            / 1000000000.0;

                /* A process reads, writes, execs and moves only while it runs, so what it did
                 * since the last sample is read only when it ran since. */
                ps->sample->read_bytes = ps->sample->prev->read_bytes;
                ps->sample->write_bytes = ps->sample->prev->write_bytes;
                if (ps->sample->prev == ps->first ||
                    ps->sample->runtime > ps->sample->prev->runtime) {
                        pid_read_identity(procfd, ps);
                        pid_read_io(procfd, ps->pid, ps->sample);
                }

                if (!arg_pss)
                        goto next;

                /* Pss */
                if (!ps->smaps) {
                        /* smaps_rollup was introduced in kernel 4.14 */
                        sprintf(filename, "%d/smaps_rollup", pid);
                        fd = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                        if (fd < 0) {
                                sprintf(filename, "%d/smaps", pid);
                                /* If we can't open smaps_rollup, try with smaps */
                                fd = openat(procfd, filename, O_RDONLY|O_CLOEXEC);
                        }
                        if (fd < 0)
                                goto next;
                        ps->smaps = fdopen(fd, "re");
                        if (!ps->smaps) {
                                close(fd);
                                goto next;
                        }
                        setvbuf(ps->smaps, smaps_buf, _IOFBF, sizeof(smaps_buf));
                } else {
                        rewind(ps->smaps);
                }

                /* Sum all 'Pss:' lines (this is needed when we are not
                 * reading smaps_rollup).
                 * When reading smaps_rollup, only one 'Pss:' entry will be
                 * present.
                 */
                ps->sample->pss = 0;
                while (fgets(buf, sizeof(buf), ps->smaps) != NULL) {
                        if(strncmp(buf, "Pss:", 4) == 0) {
                                /* read the Pss line */
                                ps->sample->pss += atoi(buf + 4);
                        }
                }

                if (ps->sample->pss > ps->pss_max)
                        ps->pss_max = ps->sample->pss;

next:
                ps->still_running = true;
        }

        garbage_collect_dead_processes(ps_first);

        return 0;
}
