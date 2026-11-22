#pragma once

/***
  This file is part of systemd-bootchart.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.
***/

#include <stdio.h>

#include "bootchart.h"

int json_do(FILE *of,
            struct list_sample_data *head,
            struct ps_struct *ps_first,
            int n_cpus,
            double graph_start,
            double interval,
            int overrun,
            double sampler_cpu);
