/***
  This file is part of systemd-bootchart.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.
***/

/*
 * The chart's numbers, beside the SVG, for a program to compare two boots by: the system's
 * counters at every sample, and every process's totals. Counters are written as the kernel
 * keeps them, cumulative, so a reader takes the differences it needs over the intervals it
 * chooses. Times are seconds on the chart's clock: since boot, or since the sampler started
 * with --rel.
 *
 * "samples" holds one row per sample, oldest first, whose values "sample_columns" names:
 * the sample's time; /proc/schedstat's run and wait time summed over the CPUs, in ns;
 * /proc/vmstat's pgpgin and pgpgout, in KiB; and /proc/pressure's some and full totals for
 * cpu, io and memory, in us.
 *
 * sampler_cpu_ns is the CPU time the sampler itself took to take the samples, which the
 * system's run time includes and which the processes it charted could not use.
 *
 * A process's cpu_ns, wait_ns, read_bytes and write_bytes are its totals at the last sample
 * that saw it: for a process already running when the chart started, they include what it did
 * before. first_seen and last_seen are the times of the samples that saw it first and last.
 */

#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "alloc-util.h"
#include "json.h"
#include "list.h"
#include "store.h"
#include "utf8.h"

static void json_string(FILE *of, const char *s) {
        _cleanup_free_ char *escaped = NULL;
        const unsigned char *p;

        if (!s) {
                fputs("null", of);
                return;
        }

        if (!utf8_is_printable(s, strlen(s))) {
                escaped = utf8_escape_non_printable(s);
                if (escaped)
                        s = escaped;
        }

        fputc('"', of);
        for (p = (const unsigned char *) s; *p; p++) {
                if (*p == '"' || *p == '\\')
                        fprintf(of, "\\%c", *p);
                else if (*p < 0x20)
                        fprintf(of, "\\u%04x", *p);
                else
                        fputc(*p, of);
        }
        fputc('"', of);
}

static struct list_sample_data *oldest(struct list_sample_data *head) {
        struct list_sample_data *tail = head;

        LIST_FIND_TAIL(link, head, tail);
        return tail;
}

int json_do(FILE *of,
            struct list_sample_data *head,
            struct ps_struct *ps_first,
            int n_cpus,
            double graph_start,
            double interval,
            int overrun,
            double sampler_cpu) {

        struct list_sample_data *s;
        struct ps_struct *ps;
        const char *sep;

        fprintf(of, "{\"version\": 1, \"hz\": %g, \"interval\": %g, \"overrun\": %d, \"relative\": %s, \"cpus\": %d, \"sampler_cpu_ns\": %.0f,\n",
                arg_hz, interval / 1000000000.0, overrun, arg_relative ? "true" : "false", n_cpus, sampler_cpu * 1000000000.0);

        fputs("\"sample_columns\": [\"time\", \"cpu_run_ns\", \"cpu_wait_ns\", \"pgpgin_kb\", \"pgpgout_kb\", "
              "\"cpu_some_us\", \"cpu_full_us\", \"io_some_us\", \"io_full_us\", \"memory_some_us\", \"memory_full_us\"],\n", of);

        fputs("\"samples\": [", of);
        sep = "\n";
        for (s = oldest(head); s; s = s->link_prev) {
                double run = 0, wait = 0;
                int c;

                for (c = 0; c < n_cpus; c++) {
                        run += s->runtime[c];
                        wait += s->waittime[c];
                }

                fprintf(of, "%s[%.4f,%.0f,%.0f,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]",
                        sep, s->sampletime - graph_start, run, wait, s->blockstat.bi, s->blockstat.bo,
                        s->pressure[PRESSURE_CPU][PRESSURE_SOME], s->pressure[PRESSURE_CPU][PRESSURE_FULL],
                        s->pressure[PRESSURE_IO][PRESSURE_SOME], s->pressure[PRESSURE_IO][PRESSURE_FULL],
                        s->pressure[PRESSURE_MEMORY][PRESSURE_SOME], s->pressure[PRESSURE_MEMORY][PRESSURE_FULL]);
                sep = ",\n";
        }
        fputs("\n],\n", of);

        fputs("\"processes\": [", of);
        sep = "\n";
        for (ps = ps_first->next_ps; ps; ps = ps->next_ps) {
                fprintf(of, "%s{\"pid\": %d, \"ppid\": %d, \"name\": ", sep, ps->pid, ps->ppid);
                json_string(of, ps->name);
                fputs(", \"cgroup\": ", of);
                json_string(of, ps->cgroup);
                fputs(", \"unit\": ", of);
                json_string(of, ps_unit(ps));
                fprintf(of, ", \"first_seen\": %.4f, \"last_seen\": %.4f, \"cpu_ns\": %.0f, \"wait_ns\": %.0f, "
                        "\"read_bytes\": %" PRIu64 ", \"write_bytes\": %" PRIu64 ", \"pss_max_kb\": %d}",
                        ps->first->sampledata->sampletime - graph_start,
                        ps->last->sampledata->sampletime - graph_start,
                        ps->last->runtime - ps->first->runtime,
                        ps->last->waittime - ps->first->waittime,
                        ps->last->read_bytes,
                        ps->last->write_bytes,
                        ps->pss_max);
                sep = ",\n";
        }
        fputs("\n]}\n", of);

        return ferror(of) ? -EIO : 0;
}
