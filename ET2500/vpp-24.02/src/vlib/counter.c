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
 * counter.c: simple and packet/byte counters
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
#include <vlib/stats/stats.h>

void
vlib_clear_simple_counters (vlib_simple_counter_main_t * cm)
{
  counter_t *my_counters;
  uword i, j;

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];

      for (j = 0; j < vec_len (my_counters); j++)
	{
	  my_counters[j] = 0;
	}
    }
}

void
vlib_clear_combined_counters (vlib_combined_counter_main_t * cm)
{
  vlib_counter_t *my_counters;
  uword i, j;

  for (i = 0; i < vec_len (cm->counters); i++)
    {
      my_counters = cm->counters[i];

      for (j = 0; j < vec_len (my_counters); j++)
	{
	  my_counters[j].packets = 0;
	  my_counters[j].bytes = 0;
	}
    }
}

void vlib_acl_del_set_counters(vlib_combined_counter_main_t * cm, int place, int old_len, int new_len, int step)
{
    int i = 0;
    int j = 0;
    vlib_counter_t *my_counters;

    for (i = 0; i < vec_len (cm->counters); i++)
    {
        my_counters = cm->counters[i];

        for (j = place; j < new_len; j++)
        {
            my_counters[j].packets = my_counters[j + step].packets;
            my_counters[j].bytes = my_counters[j + step].bytes;
        }
    }
}

void vlib_acl_add_set_counters(vlib_combined_counter_main_t * cm, int place, int old_len, int new_len, int step)
{
    int i = 0;
    int j = 0;
    vlib_counter_t *my_counters;

    for (i = 0; i < vec_len (cm->counters); i++)
    {
        my_counters = cm->counters[i];
        if (place == old_len)
        {
            my_counters[place].packets = 0;
            my_counters[place].bytes = 0;
        }

        else
        {
            for (j = old_len - 1; j >= place; j--)
            {
                my_counters[j + step].packets = my_counters[j].packets;
                my_counters[j + step].bytes = my_counters[j].bytes;
            }

            for (j = place; j < place + step; j++)
            {
                my_counters[j].packets = 0;
                my_counters[j].bytes = 0;
            }
        }
    }
}

void vlib_set_combined_counters (vlib_combined_counter_main_t * cm, int flag, int place, int old_len, int new_len)
{
    vlib_counter_t *my_counters;
    uword j;

    if (flag == ACL_DEL_RULE_ONE)
    {
        vlib_acl_del_set_counters(cm, place, old_len, new_len, 1);
    }

    else if (flag == ACL_DEL_RULE_TWO)
    {
        vlib_acl_del_set_counters(cm, place, old_len, new_len, 2);
    }

    else if (flag == ACL_DEL_RULE_ONE_REP_ONE)
    {
        for (j = 0; j < vec_len (cm->counters); j++)
        {
            my_counters = cm->counters[j];
            my_counters[place].packets = 0;
            my_counters[place].bytes = 0;
        }

        vlib_acl_del_set_counters(cm, place + 1, old_len, new_len, 1);
    }

    else if (flag == ACL_ADD_RULE_ONE)
    {
        vlib_acl_add_set_counters(cm, place, old_len, new_len, 1);
    }

    else if (flag == ACL_ADD_RULE_TWO)
    {
        vlib_acl_add_set_counters(cm, place, old_len, new_len, 2);
    }

    else if (flag == ACL_ADD_RULE_ONE_REP_ONE)
    {
        vlib_acl_add_set_counters(cm, place + 1, old_len, new_len, 1);
        for (j = 0; j < vec_len (cm->counters); j++)
        {
            my_counters = cm->counters[j];
            my_counters[place].packets = 0;
            my_counters[place].bytes = 0;
        }
    }

    else if (flag == ACL_REPLACE_RULE_ONE)
    {
        for (j = 0; j < vec_len (cm->counters); j++)
        {
            my_counters = cm->counters[j];
            my_counters[place].packets = 0;
            my_counters[place].bytes = 0;
        }
    }

    else if (flag == ACL_REPLACE_RULE_TWO)
    {
        for (j = 0; j < vec_len (cm->counters); j++)
        {
            my_counters = cm->counters[j];
            my_counters[place].packets = 0;
            my_counters[place].bytes = 0;

            my_counters[place + 1].packets = 0;
            my_counters[place + 1].bytes = 0;
        }
    }

}

void
vlib_validate_simple_counter (vlib_simple_counter_main_t * cm, u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  char *name = cm->stat_segment_name ? cm->stat_segment_name : cm->name;

  if (name == 0)
    {
      if (cm->counters == 0)
	cm->stats_entry_index = ~0;
      vec_validate (cm->counters, tm->n_vlib_mains - 1);
      for (int i = 0; i < tm->n_vlib_mains; i++)
	vec_validate_aligned (cm->counters[i], index, CLIB_CACHE_LINE_BYTES);
      return;
    }

  if (cm->counters == 0)
    cm->stats_entry_index = vlib_stats_add_counter_vector ("%s", name);

  vlib_stats_validate (cm->stats_entry_index, tm->n_vlib_mains - 1, index);
  cm->counters = vlib_stats_get_entry_data_pointer (cm->stats_entry_index);
}

void
vlib_free_simple_counter (vlib_simple_counter_main_t * cm)
{
  if (cm->stats_entry_index == ~0)
    {
      for (int i = 0; i < vec_len (cm->counters); i++)
	vec_free (cm->counters[i]);
      vec_free (cm->counters);
    }
  else
    {
      vlib_stats_remove_entry (cm->stats_entry_index);
      cm->counters = NULL;
    }
}

void
vlib_validate_combined_counter (vlib_combined_counter_main_t * cm, u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  char *name = cm->stat_segment_name ? cm->stat_segment_name : cm->name;

  if (name == 0)
    {
      if (cm->counters == 0)
	cm->stats_entry_index = ~0;
      vec_validate (cm->counters, tm->n_vlib_mains - 1);
      for (int i = 0; i < tm->n_vlib_mains; i++)
	vec_validate_aligned (cm->counters[i], index, CLIB_CACHE_LINE_BYTES);
      return;
    }

  if (cm->counters == 0)
    cm->stats_entry_index = vlib_stats_add_counter_pair_vector ("%s", name);

  vlib_stats_validate (cm->stats_entry_index, tm->n_vlib_mains - 1, index);
  cm->counters = vlib_stats_get_entry_data_pointer (cm->stats_entry_index);
}

int
  vlib_validate_combined_counter_will_expand
  (vlib_combined_counter_main_t * cm, u32 index)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int i;
  void *oldheap = vlib_stats_set_heap ();

  /* Possibly once in recorded history */
  if (PREDICT_FALSE (vec_len (cm->counters) == 0))
    {
      clib_mem_set_heap (oldheap);
      return 1;
    }

  for (i = 0; i < tm->n_vlib_mains; i++)
    {
      /* Trivially OK, and proves that index >= vec_len(...) */
      if (index < vec_len (cm->counters[i]))
	continue;
      if (vec_resize_will_expand (cm->counters[i],
				  index - vec_len (cm->counters[i]) +
				    1 /* length_increment */))
	{
	  clib_mem_set_heap (oldheap);
	  return 1;
	}
    }
  clib_mem_set_heap (oldheap);
  return 0;
}

void
vlib_free_combined_counter (vlib_combined_counter_main_t * cm)
{
  if (cm->stats_entry_index == ~0)
    {
      for (int i = 0; i < vec_len (cm->counters); i++)
	vec_free (cm->counters[i]);
      vec_free (cm->counters);
    }
  else
    {
      vlib_stats_remove_entry (cm->stats_entry_index);
      cm->counters = NULL;
    }
}

u32
vlib_combined_counter_n_counters (const vlib_combined_counter_main_t * cm)
{
  ASSERT (cm->counters);
  return (vec_len (cm->counters[0]));
}

u32
vlib_simple_counter_n_counters (const vlib_simple_counter_main_t * cm)
{
  ASSERT (cm->counters);
  return (vec_len (cm->counters[0]));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
