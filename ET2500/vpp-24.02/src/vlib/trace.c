/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * trace.c: VLIB trace buffer.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/classify/vnet_classify.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

u8 *vnet_trace_placeholder;

/* Helper function for nodes which only trace buffer data. */
void
vlib_trace_frame_buffers_only (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       u32 * buffers,
			       uword n_buffers,
			       uword next_buffer_stride,
			       uword n_buffer_data_bytes_in_trace)
{
  u32 n_left, *from;

  n_left = n_buffers;
  from = buffers;

  while (n_left >= 4)
    {
      u32 bi0, bi1;
      vlib_buffer_t *b0, *b1;
      u8 *t0, *t1;

      /* Prefetch next iteration. */
      vlib_prefetch_buffer_with_index (vm, from[2], LOAD);
      vlib_prefetch_buffer_with_index (vm, from[3], LOAD);

      bi0 = from[0];
      bi1 = from[1];

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, n_buffer_data_bytes_in_trace);
	  clib_memcpy_fast (t0, b0->data + b0->current_data,
			    n_buffer_data_bytes_in_trace);
	}
      if (b1->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t1 = vlib_add_trace (vm, node, b1, n_buffer_data_bytes_in_trace);
	  clib_memcpy_fast (t1, b1->data + b1->current_data,
			    n_buffer_data_bytes_in_trace);
	}
      from += 2;
      n_left -= 2;
    }

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u8 *t0;

      bi0 = from[0];

      b0 = vlib_get_buffer (vm, bi0);

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
	{
	  t0 = vlib_add_trace (vm, node, b0, n_buffer_data_bytes_in_trace);
	  clib_memcpy_fast (t0, b0->data + b0->current_data,
			    n_buffer_data_bytes_in_trace);
	}
      from += 1;
      n_left -= 1;
    }
}

/* Free up all trace buffer memory. */
void
clear_trace_buffer (void)
{
  int i;
  vlib_trace_main_t *tm;

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;

      tm->trace_enable = 0;
      vec_free (tm->nodes);
    }

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;

      for (i = 0; i < vec_len (tm->trace_buffer_pool); i++)
	if (!pool_is_free_index (tm->trace_buffer_pool, i))
	  vec_free (tm->trace_buffer_pool[i]);
      pool_free (tm->trace_buffer_pool);
    }
}

u8 *
format_vlib_trace (u8 * s, va_list * va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_trace_header_t *h = va_arg (*va, vlib_trace_header_t *);
  vlib_trace_header_t *e = vec_end (h);
  vlib_node_t *node, *prev_node;
  clib_time_t *ct = &vm->clib_time;
  f64 t;

  prev_node = 0;
  while (h < e)
    {
      node = vlib_get_node (vm, h->node_index);

      if (node != prev_node)
	{
	  t =
	    (h->time - vm->cpu_time_main_loop_start) * ct->seconds_per_clock;
	  s =
	    format (s, "\n%U: %v", format_time_interval, "h:m:s:u", t,
		    node->name);
	}
      prev_node = node;

      if (node->format_trace)
	s = format (s, "\n  %U", node->format_trace, vm, node, h->data);
      else
	s = format (s, "\n  %U", node->format_buffer, h->data);

      h = vlib_trace_header_next (h);
    }

  return s;
}

/* Root of all trace cli commands. */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (trace_cli_command,static) = {
  .path = "trace",
  .short_help = "Packet tracer commands",
};
/* *INDENT-ON* */

int
trace_time_cmp (void *a1, void *a2)
{
  vlib_trace_header_t **t1 = a1;
  vlib_trace_header_t **t2 = a2;
  i64 dt = t1[0]->time - t2[0]->time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

/*
 * Return 1 if this packet passes the trace filter, or 0 otherwise
 */
u32
filter_accept (vlib_trace_main_t * tm, vlib_trace_header_t * h)
{
  vlib_trace_header_t *e = vec_end (h);

  if (tm->filter_flag == 0)
    return 1;

  /*
   * When capturing a post-mortem dispatch trace,
   * toss all existing traces once per dispatch cycle.
   * So we can trace 4 billion pkts without running out of
   * memory...
   */
  if (tm->filter_flag == FILTER_FLAG_POST_MORTEM)
    return 0;

  if (tm->filter_flag == FILTER_FLAG_INCLUDE)
    {
      while (h < e)
	{
	  if (h->node_index == tm->filter_node_index)
	    return 1;
	  h = vlib_trace_header_next (h);
	}
      return 0;
    }
  else				/* FILTER_FLAG_EXCLUDE */
    {
      while (h < e)
	{
	  if (h->node_index == tm->filter_node_index)
	    return 0;
	  h = vlib_trace_header_next (h);
	}
      return 1;
    }

  return 0;
}

/*
 * Remove traces from the trace buffer pool that don't pass the filter
 */
void
trace_apply_filter (vlib_main_t * vm)
{
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_trace_header_t **h;
  vlib_trace_header_t ***traces_to_remove = 0;
  u32 index;
  u32 trace_index;
  u32 n_accepted;

  u32 accept;

  if (tm->filter_flag == FILTER_FLAG_NONE)
    return;

  /*
   * Ideally we would retain the first N traces that pass the filter instead
   * of any N traces.
   */
  n_accepted = 0;
  /* *INDENT-OFF* */
  pool_foreach (h, tm->trace_buffer_pool)
    {
      accept = filter_accept(tm, h[0]);

      if ((n_accepted == tm->filter_count) || !accept)
          vec_add1 (traces_to_remove, h);
      else
          n_accepted++;
  }
  /* *INDENT-ON* */

  /* remove all traces that we don't want to keep */
  for (index = 0; index < vec_len (traces_to_remove); index++)
    {
      trace_index = traces_to_remove[index] - tm->trace_buffer_pool;
      vec_set_len (tm->trace_buffer_pool[trace_index], 0);
      pool_put_index (tm->trace_buffer_pool, trace_index);
    }

  vec_free (traces_to_remove);
}

static clib_error_t *
cli_show_trace_buffer (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_trace_main_t *tm;
  vlib_trace_header_t **h, **traces;
  u32 i, index = 0;
  char *fmt;
  u8 *s = 0;
  u32 max;

  /*
   * By default display only this many traces. To display more, explicitly
   * specify a max. This prevents unexpectedly huge outputs.
   */
  max = 50;
  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max %d", &max))
	;
      else
	return clib_error_create ("expected 'max COUNT', got `%U'",
				  format_unformat_error, input);
    }


  /* Get active traces from pool. */

  foreach_vlib_main ()
    {
      fmt = "------------------- Start of thread %d %s -------------------\n";
      s = format (s, fmt, index, vlib_worker_threads[index].name);

      tm = &this_vlib_main->trace_main;

      trace_apply_filter (this_vlib_main);

      traces = 0;
      pool_foreach (h, tm->trace_buffer_pool)
	{
	  vec_add1 (traces, h[0]);
	}

      if (vec_len (traces) == 0)
	{
	  s = format (s, "No packets in trace buffer\n");
	  goto done;
	}

      /* Sort them by increasing time. */
      vec_sort_with_function (traces, trace_time_cmp);

      for (i = 0; i < vec_len (traces); i++)
	{
	  if (i == max)
	    {
	      char *warn = "Limiting display to %d packets."
			   " To display more specify max.";
	      vlib_cli_output (vm, warn, max);
	      s = format (s, warn, max);
	      goto done;
	    }

	  s = format (s, "Packet %d\n%U\n\n", i + 1, format_vlib_trace, vm,
		      traces[i]);
	}

    done:
      vec_free (traces);

      index++;
    }

  vlib_cli_output (vm, "%v", s);
  vec_free (s);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_trace_cli,static) = {
  .path = "show trace",
  .short_help = "Show trace buffer [max COUNT]",
  .function = cli_show_trace_buffer,
};
/* *INDENT-ON* */

static int
file_exists (u8 *fname)
{
  FILE *fp = 0;
  fp = fopen ((char *) fname, "r");
  if (fp)
    {
      fclose (fp);
      return 1;
    }
  return 0;
}

static clib_error_t *
cli_dump_trace_buffer (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_trace_main_t *tm;
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_trace_header_t **h, **traces;
  u32 i, idx = 0;
  char *fmt;
  u8 *s = 0;
  u32 max;
  u8 *filename = 0;
  u8 *chroot_filename = 0;
  FILE *fp;

  if (!unformat_user (input, unformat_line_input, line_input))
      return 0;

  /* default all to file*/
  max = (u32)-1;
  while (unformat_check_input (line_input) != (uword) UNFORMAT_END_OF_INPUT)
  {
      if (unformat (line_input, "file %s", &filename))
          ;
      else if (unformat (line_input, "max %d", &max))
          ;
      else
          return clib_error_create ("expected 'max COUNT', got `%U'",
                  format_unformat_error, input);
  }

  if (strstr ((char *) filename, "..") ||
          index ((char *) filename, '/'))
  {
      vlib_cli_output (vm, "illegal characters in filename '%s'",
              filename);
      goto out;
  }

  chroot_filename = format (0, "/%s%c", filename, 0);

  vec_free (filename);

  if (file_exists (chroot_filename))
  {
      vlib_cli_output (vm, "file exists: %s\n", chroot_filename);
      goto out;
  }

  fp = fopen ((char *) chroot_filename, "w");
  if (fp == NULL)
  {
      vlib_cli_output (vm, "Couldn't create %s\n", chroot_filename);
      goto out;
  }
  //dump trace
  foreach_vlib_main ()
  {
      fmt = "------------------- Start of thread %d %s -------------------\n";
      s = format (s, fmt, idx, vlib_worker_threads[idx].name);

      tm = &this_vlib_main->trace_main;

      trace_apply_filter (this_vlib_main);

      traces = 0;
      pool_foreach (h, tm->trace_buffer_pool)
      {
          vec_add1 (traces, h[0]);
      }

      if (vec_len (traces) == 0)
      {
          s = format (s, "No packets in trace buffer\n");
          goto done;
      }

      /* Sort them by increasing time. */
      vec_sort_with_function (traces, trace_time_cmp);

      for (i = 0; i < vec_len (traces); i++)
      {
          if (i == max)
          {
              char *warn = "Limiting display to %d packets."
                  " To display more specify max.";
              vlib_cli_output (vm, warn, max);
              s = format (s, warn, max);
              goto done;
          }

          s = format (s, "Packet %d\n%U\n\n", i + 1, format_vlib_trace, vm,
                  traces[i]);
      }

done:
      fwrite(s, 1, vec_len(s), fp);

      vec_free (traces);
      idx++;
      vec_free(s);
  }
  fclose (fp);
out:
  return 0;
}

VLIB_CLI_COMMAND (dump_trace_cli,static) = {
  .path = "trace dump",
  .short_help = "trace dump file <file> [max COUNT]",
  .function = cli_dump_trace_buffer,
};

int vlib_enable_disable_pkt_trace_filter (int enable) __attribute__ ((weak));

int
vlib_enable_disable_pkt_trace_filter (int enable)
{
  return 0;
}

void
vlib_trace_stop_and_clear (void)
{
  vlib_enable_disable_pkt_trace_filter (0);	/* disble tracing */
  clear_trace_buffer ();
}


void
trace_update_capture_options (u32 add, u32 node_index, u32 filter, u8 verbose)
{
  vlib_trace_main_t *tm;
  vlib_trace_node_t *tn;

  if (add == ~0)
    add = 50;

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;
      tm->verbose = verbose;
      vec_validate (tm->nodes, node_index);
      tn = tm->nodes + node_index;

      /*
       * Adding 0 makes no real sense, and there wa no other way
       * to explicilty zero-out the limits and count, so make
       * an "add 0" request really be "set to 0".
       */
      if (add == 0)
	  tn->limit = tn->count = 0;
      else
	  tn->limit += add;
    }

  foreach_vlib_main ()
    {
      tm = &this_vlib_main->trace_main;
      tm->trace_enable = 1;
    }

  vlib_enable_disable_pkt_trace_filter (! !filter);
}

static clib_error_t *
cli_add_trace_buffer (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_node_t *node;
  u32 node_index, add;
  u8 verbose = 0;
  int filter = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (vnet_trace_placeholder == 0)
    vec_validate_aligned (vnet_trace_placeholder, 2048,
			  CLIB_CACHE_LINE_BYTES);

  while (unformat_check_input (line_input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U %d",
		    unformat_vlib_node, vm, &node_index, &add))
	;
      else if (unformat (line_input, "verbose"))
	verbose = 1;
      else if (unformat (line_input, "filter"))
	filter = 1;
      else
	{
	  error = clib_error_create ("expected NODE COUNT, got `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  node = vlib_get_node (vm, node_index);

  if ((node->flags & VLIB_NODE_FLAG_TRACE_SUPPORTED) == 0)
    {
      error = clib_error_create ("node '%U' doesn't support per-node "
				 "tracing. There may be another way to "
				 "initiate trace on this node.",
				 format_vlib_node_name, vm, node_index);
      goto done;
    }

  trace_update_capture_options (add, node_index, filter, verbose);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (add_trace_cli,static) = {
  .path = "trace add",
  .short_help = "trace add <input-graph-node> <add'l-pkts-for-node-> [filter] [verbose]",
  .function = cli_add_trace_buffer,
};
/* *INDENT-ON* */

/*
 * Configure a filter for packet traces.
 *
 * This supplements the packet trace feature so that only packets matching
 * the filter are included in the trace. Currently the only filter is to
 * keep packets that include a certain node in the trace or exclude a certain
 * node in the trace.
 *
 * The count of traced packets in the "trace add" command is still used to
 * create a certain number of traces. The "trace filter" command specifies
 * how many of those packets should be retained in the trace.
 *
 * For example, 1Mpps of traffic is arriving and one of those packets is being
 * dropped. To capture the trace for only that dropped packet, you can do:
 *     trace filter include error-drop 1
 *     trace add dpdk-input 1000000
 *     <wait one second>
 *     show trace
 *
 * Note that the filter could be implemented by capturing all traces and just
 * reducing traces displayed by the "show trace" function. But that would
 * require a lot of memory for storing the traces, making that infeasible.
 *
 * To remove traces from the trace pool that do not include a certain node
 * requires that the trace be "complete" before applying the filter. To
 * accomplish this, the trace pool is filtered upon each iteraction of the
 * main vlib loop. Doing so keeps the number of allocated traces down to a
 * reasonably low number. This requires that tracing for a buffer is not
 * performed after the vlib main loop interation completes. i.e. you can't
 * save away a buffer temporarily then inject it back into the graph and
 * expect that the trace_index is still valid (such as a traffic manager might
 * do). A new trace buffer should be allocated for those types of packets.
 *
 * The filter can be extended to support multiple nodes and other match
 * criteria (e.g. input sw_if_index, mac address) but for now just checks if
 * a specified node is in the trace or not in the trace.
 */

void
trace_filter_set (u32 node_index, u32 flag, u32 count)
{
  foreach_vlib_main ()
    {
      vlib_trace_main_t *tm;

      tm = &this_vlib_main->trace_main;
      tm->filter_node_index = node_index;
      tm->filter_flag = flag;
      tm->filter_count = count;

      /*
       * Clear the trace limits to stop any in-progress tracing
       * Prevents runaway trace allocations when the filter changes
       * (or is removed)
       */
      vec_free (tm->nodes);
    }
}


static clib_error_t *
cli_filter_trace (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 filter_node_index;
  u32 filter_flag;
  u32 filter_count;

  if (unformat (input, "include %U %d",
		unformat_vlib_node, vm, &filter_node_index, &filter_count))
    {
      filter_flag = FILTER_FLAG_INCLUDE;
    }
  else if (unformat (input, "exclude %U %d",
		     unformat_vlib_node, vm, &filter_node_index,
		     &filter_count))
    {
      filter_flag = FILTER_FLAG_EXCLUDE;
    }
  else if (unformat (input, "none"))
    {
      filter_flag = FILTER_FLAG_NONE;
      filter_node_index = 0;
      filter_count = 0;
    }
  else
    return
      clib_error_create
      ("expected 'include NODE COUNT' or 'exclude NODE COUNT' or 'none', got `%U'",
       format_unformat_error, input);

  trace_filter_set (filter_node_index, filter_flag, filter_count);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (filter_trace_cli,static) = {
  .path = "trace filter",
  .short_help = "trace filter none | [include|exclude] NODE COUNT",
  .function = cli_filter_trace,
};
/* *INDENT-ON* */

static clib_error_t *
cli_clear_trace_buffer (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vlib_trace_stop_and_clear ();
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_trace_cli,static) = {
  .path = "clear trace",
  .short_help = "Clear trace buffer and free memory",
  .function = cli_clear_trace_buffer,
};
/* *INDENT-ON* */

/* Placeholder function to get us linked in. */
void
vlib_trace_cli_reference (void)
{
}

void *
vlib_add_trace (vlib_main_t * vm,
		vlib_node_runtime_t * r, vlib_buffer_t * b, u32 n_data_bytes)
{
  return vlib_add_trace_inline (vm, r, b, n_data_bytes);
}

vlib_is_packet_traced_fn_t *
vlib_is_packet_traced_function_from_name (const char *name)
{
  vlib_trace_filter_function_registration_t *reg =
    vlib_trace_filter_main.trace_filter_registration;
  while (reg)
    {
      if (clib_strcmp (reg->name, name) == 0)
	break;
      reg = reg->next;
    }
  if (!reg)
    return 0;
  return reg->function;
}

vlib_is_packet_traced_fn_t *
vlib_is_packet_traced_default_function ()
{
  vlib_trace_filter_function_registration_t *reg =
    vlib_trace_filter_main.trace_filter_registration;
  vlib_trace_filter_function_registration_t *tmp_reg = reg;
  while (reg)
    {
      if (reg->priority > tmp_reg->priority)
	tmp_reg = reg;
      reg = reg->next;
    }
  return tmp_reg->function;
}

static clib_error_t *
vlib_trace_filter_function_init (vlib_main_t *vm)
{
  vlib_is_packet_traced_fn_t *default_fn =
    vlib_is_packet_traced_default_function ();
  foreach_vlib_main ()
    {
      vlib_trace_main_t *tm = &this_vlib_main->trace_main;
      tm->current_trace_filter_function = default_fn;
    }
  return 0;
}

vlib_trace_filter_main_t vlib_trace_filter_main;

VLIB_INIT_FUNCTION (vlib_trace_filter_function_init);

static clib_error_t *
show_trace_filter_function (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  vlib_trace_filter_main_t *tfm = &vlib_trace_filter_main;
  vlib_trace_main_t *tm = &vm->trace_main;
  vlib_is_packet_traced_fn_t *current_trace_filter_fn =
    tm->current_trace_filter_function;
  vlib_trace_filter_function_registration_t *reg =
    tfm->trace_filter_registration;

  while (reg)
    {
      vlib_cli_output (vm, "%sname:%s description: %s priority: %u",
		       reg->function == current_trace_filter_fn ? "(*) " : "",
		       reg->name, reg->description, reg->priority);
      reg = reg->next;
    }
  return 0;
}

VLIB_CLI_COMMAND (show_trace_filter_function_cli, static) = {
  .path = "show trace filter function",
  .short_help = "show trace filter function",
  .function = show_trace_filter_function,
};

uword
unformat_vlib_trace_filter_function (unformat_input_t *input, va_list *args)
{
  vlib_is_packet_traced_fn_t **res =
    va_arg (*args, vlib_is_packet_traced_fn_t **);
  vlib_trace_filter_main_t *tfm = &vlib_trace_filter_main;

  vlib_trace_filter_function_registration_t *reg =
    tfm->trace_filter_registration;
  while (reg)
    {
      if (unformat (input, reg->name))
	{
	  *res = reg->function;
	  return 1;
	}
      reg = reg->next;
    }
  return 0;
}

void
vlib_set_trace_filter_function (vlib_is_packet_traced_fn_t *x)
{
  foreach_vlib_main ()
    {
      this_vlib_main->trace_main.current_trace_filter_function = x;
    }
}

static clib_error_t *
set_trace_filter_function (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_is_packet_traced_fn_t *res = 0;
  clib_error_t *error = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vlib_trace_filter_function,
		    &res))
	;
      else
	{
	  error = clib_error_create (
	    "expected valid trace filter function, got `%U'",
	    format_unformat_error, line_input);
	  goto done;
	}
    }
  vlib_set_trace_filter_function (res);

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (set_trace_filter_function_cli, static) = {
  .path = "set trace filter function",
  .short_help = "set trace filter function <func_name>",
  .function = set_trace_filter_function,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
