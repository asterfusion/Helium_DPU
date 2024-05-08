/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
 */

#ifdef USE_BUFFER_POOL

#include "octeon_main.h"

static int malloc_buffer(octeon_device_t *, OCTEON_BUFPOOL, int, int);
static void free_buffer(octeon_device_t *, OCTEON_BUFPOOL);
static void put_buffer(cavium_buffer_t *, int);
static uint8_t *get_buffer(void *, cavium_buffer_t *);

cavium_list_t allocated_list_head = { NULL, NULL };

/* Initial Buffer count */
uint32_t buffer_stats[BUF_POOLS];

/* Allocated buffers */
uint32_t alloc_buffer_stats[BUF_POOLS];

/* Buffers in fragmented pool */
uint32_t fragment_buf_stats[BUF_POOLS];

/* Buffers given for fragmentation */
uint32_t other_pools[BUF_POOLS];

/******************************************************** 
 * Function : octeon_init_buffer_pool
 *
 * Arguments    : octeon_device_t *, cavium_general_config *
 * Return Value : Returns the status 0 (success) or
 *                1 (failure)
 * 
 * This function is used to intialize the buffer pool of 
 * the driver.The individual buffer pools are of size
 * 1k,2k,4k,8k,16k and 32k
 *
 ********************************************************/

uint32_t
octeon_init_buffer_pool(octeon_device_t * octeon_dev,
			octeon_bufpool_config_t * gconfig)
{
	uint16_t i;

	cavium_spin_lock_init(&octeon_dev->fragment_lock);
	cavium_spin_lock_init(&(octeon_dev->buf[huge].buffer_lock));
	cavium_spin_lock_init(&(octeon_dev->buf[large].buffer_lock));
	cavium_spin_lock_init(&(octeon_dev->buf[medium].buffer_lock));
	cavium_spin_lock_init(&(octeon_dev->buf[small].buffer_lock));
	cavium_spin_lock_init(&(octeon_dev->buf[tiny].buffer_lock));
	cavium_spin_lock_init(&(octeon_dev->buf[ex_tiny].buffer_lock));

	/* 32 kB buffers */
	if (malloc_buffer(octeon_dev, huge, gconfig->huge_buffer_max,
			  HUGE_BUFFER_CHUNK_SIZE)) {
		cavium_error("OCTEON init_buffer_pool: failed to alloc huge\n");
		goto failed;
	}
	buffer_stats[huge] = gconfig->huge_buffer_max;

	/* 16 kB buffers */
	if (malloc_buffer(octeon_dev, large, gconfig->large_buffer_max,
			  LARGE_BUFFER_CHUNK_SIZE)) {
		cavium_error
		    ("OCTEON init_buffer_pool: failed to alloc large\n");
		goto failed;
	}
	buffer_stats[large] = gconfig->large_buffer_max;

	/* 8 kB buffers */
	if (malloc_buffer(octeon_dev, medium, gconfig->medium_buffer_max,
			  MEDIUM_BUFFER_CHUNK_SIZE)) {
		cavium_error
		    ("OCTEON init_buffer_pool: failed to alloc medium\n");
		goto failed;
	}
	buffer_stats[medium] = gconfig->medium_buffer_max;

	/* 4 kB buffers */
	if (malloc_buffer(octeon_dev, small, gconfig->small_buffer_max,
			  SMALL_BUFFER_CHUNK_SIZE)) {
		cavium_error
		    ("OCTEON init_buffer_pool: failed to alloc small\n");
		goto failed;
	}
	buffer_stats[small] = gconfig->small_buffer_max;

	/*  2 kB buffers */
	if (malloc_buffer(octeon_dev, tiny, gconfig->tiny_buffer_max,
			  TINY_BUFFER_CHUNK_SIZE)) {
		cavium_error("OCTEON init_buffer_pool: failed to alloc tiny\n");
		goto failed;
	}
	buffer_stats[tiny] = gconfig->tiny_buffer_max;

	/* 1kB buffers */
	if (malloc_buffer(octeon_dev, ex_tiny, gconfig->ex_tiny_buffer_max,
			  EX_TINY_BUFFER_CHUNK_SIZE)) {
		cavium_error
		    ("OCTEON init_buffer_pool: failed to alloc ex_tiny\n");
		goto failed;
	}
	buffer_stats[ex_tiny] = gconfig->ex_tiny_buffer_max;

	/* List of fragmented buffers in use by applications */
	CAVIUM_INIT_LIST_HEAD(&allocated_list_head);
	for (i = 0; i < MAX_BUFFER_CHUNKS; i++) {
		octeon_dev->fragment_free_list[i] = i;
		octeon_dev->fragments[i].index = i;
	}
	octeon_dev->fragment_free_list_index = 0;
	return 0;

failed:
	octeon_delete_buffer_pool(octeon_dev);
	return 1;
}

/*************************************************** 
 * Function : octeon_delete_buffer_pool
 *
 * Arguments       : octeon_device_t *
 * Return Value    : Returns void 
 *
 * This function free the individual buffer pools 
 * of different sizes.
 *
 ***************************************************/
void octeon_delete_buffer_pool(octeon_device_t * octeon_dev)
{
	cavium_spin_lock_destroy(&(octeon_dev->buf[huge].buffer_lock));
	cavium_spin_lock_destroy(&(octeon_dev->buf[large].buffer_lock));
	cavium_spin_lock_destroy(&(octeon_dev->buf[medium].buffer_lock));
	cavium_spin_lock_destroy(&(octeon_dev->buf[small].buffer_lock));
	cavium_spin_lock_destroy(&(octeon_dev->buf[tiny].buffer_lock));
	cavium_spin_lock_destroy(&(octeon_dev->buf[ex_tiny].buffer_lock));
	free_buffer(octeon_dev, huge);
	buffer_stats[huge] = 0;
	free_buffer(octeon_dev, large);
	buffer_stats[large] = 0;
	free_buffer(octeon_dev, medium);
	buffer_stats[medium] = 0;
	free_buffer(octeon_dev, small);
	buffer_stats[small] = 0;
	free_buffer(octeon_dev, tiny);
	buffer_stats[tiny] = 0;
	free_buffer(octeon_dev, ex_tiny);
	buffer_stats[ex_tiny] = 0;
	cavium_spin_lock_destroy(&octeon_dev->fragment_lock);
}

/**************************************************** 
 * Function  : malloc_buffer
 * 
 * Arguments : octeon_device_t *, pool,int, int
 * Return Value : Type - int 
 *                Returns the error value 0 (success)
 *                and 1 (failure).
 * 
 * This function does the actual allocation of 
 * memory to a particular buffer pool
 *
 ****************************************************/

static int
malloc_buffer(octeon_device_t * octeon_dev,
	      OCTEON_BUFPOOL p, int count, int size)
{
	uint16_t i;
	cavium_buffer_t *buf = &octeon_dev->buf[p];

	buf->chunks = count;
	buf->chunk_size = size;
	buf->real_size = size + sizeof(buffer_tag);
	buf->free_list_index = 0;

	/* List of Fragmented buffers obtained */
	CAVIUM_INIT_LIST_HEAD(&buf->frags_list);

	for (i = 0; i < buf->chunks; i++) {
		buf->address[i] =
		    (uint8_t *) cavium_malloc_dma(buf->real_size,
						  __CAVIUM_MEM_ATOMIC);
		if (!buf->address[i]) {
			cavium_error
			    ("OCTEON malloc_buffer: failed for chunk=%d\n", i);
			goto failed;
		}
		buf->address_trans[i] = (uint8_t *) ((unsigned long)
						     buf->address[i] +
						     sizeof(buffer_tag));
		buf->free_list[i] = i;
		((buffer_tag *) buf->address[i])->pool = p;
		((buffer_tag *) buf->address[i])->index = i;
	}
	return 0;

failed:
	return 1;
}

/*************************************************** 
 * Function : free_buffer
 *
 * Arguments : octeon_device_t *, pool
 * Return Value : Returns void 
 *
 * This function does the actual freeing of the 
 * DMA buffer which has been allocted by the driver
 *
 ***************************************************/
void free_buffer(octeon_device_t * octeon_dev, OCTEON_BUFPOOL p)
{
	int i;
	cavium_buffer_t *buf = &octeon_dev->buf[p];

	for (i = 0; i < buf->chunks; i++) {
		if (buf->address[i])
			cavium_free_dma(buf->address[i]);
	}
	cavium_memset(buf, 0, sizeof(cavium_buffer_t));
	return;
}

/***************************************************** 
 * Function       : get_free_fragment 
 *
 * Arguments      : octeon_device_t *
 * Return Value   : Returns a free fragment of the 
 *                  type cavium_frag_buf_t *
 *
 * This function gets a free buffer fragment from the 
 * free fragment list
 *
 *****************************************************/
static cavium_frag_buf_t *get_free_fragment(octeon_device_t * octeon_dev)
{
	cavium_frag_buf_t *frag;
// *INDENT-OFF*
        int index = octeon_dev->fragment_free_list[octeon_dev->fragment_free_list_index++];
// *INDENT-ON*
	frag = &octeon_dev->fragments[index];
	return frag;
}

/*************************************************
 * Function : put_fragment
 *
 * Argument      : octeon_device_t *,cavium_frag_buf_t 
 * Return Value  : Returns void 
 *
 * This function puts back the fragment into the 
 * free pool of fragment list.
 *
 *************************************************/

static void put_fragment(octeon_device_t * octeon_dev, cavium_frag_buf_t frag)
{
	octeon_dev->fragment_free_list_index--;
	octeon_dev->fragment_free_list[octeon_dev->fragment_free_list_index] =
	    (uint16_t) frag.index;
}

/********************************************************* 
 * Function  : put_buffer
 *
 * Arguments : cavium_buffer_t *, int
 * Returns   : void
 *
 * This function puts back the buffer into the 
 * free buffer pool
 *********************************************************/

static void put_buffer(cavium_buffer_t * b, int index)
{
	unsigned long flags;

	cavium_spin_lock_irqsave(&b->buffer_lock, flags);
	b->free_list_index--;
	b->free_list[b->free_list_index] = (uint16_t) index;
	cavium_spin_unlock_irqrestore(&b->buffer_lock, flags);
}

/********************************************************* 
 * Function  : get_buffer_from_init_pool
 *
 * Arguments : void *, cavium_buffer_t *
 * Returns   : Returns the address of the buffer 
 *             of type uint8_t *  or NULL
 *
 * This function gets buffer (which has been requested)
 * from the preallocated free pool 
 *
 *********************************************************/
static uint8_t *get_buffer_from_init_pool(void *pdev, cavium_buffer_t * b)
{
	int index;
	uint8_t *ret = NULL;
	unsigned long flags;

	cavium_spin_lock_irqsave(&b->buffer_lock, flags);
	if (b->free_list_index < b->chunks) {
		/* Allocating from the free pool */
		index = b->free_list[b->free_list_index++];
		ret = b->address_trans[index];
	}
	cavium_spin_unlock_irqrestore(&b->buffer_lock, flags);
	return ret;
}

/********************************************************* 
 * Function  : get_buffer
 *
 * Arguments : void *, cavium_buffer_t *
 * Returns   : Returns the address of the buffer 
 *             of type uint8_t *  or NULL
 *
 * This function gets buffer (which has been requested)
 * from the preallocated free pool or from the fragmented
 * list of buffers obtained from higher pools
 *
 *********************************************************/
static uint8_t *get_buffer(void *pdev, cavium_buffer_t * b)
{
	octeon_device_t *octeon_dev = (octeon_device_t *) pdev;
	int index;
	uint8_t *ret = NULL;
	cavium_list_t *tmp;
	unsigned long flags;

	ret = get_buffer_from_init_pool(pdev, b);
	if (ret)
		return ret;

	/* Allocating from the fragmented list of buffers 
	 * obtained from higher pools*/
	cavium_spin_lock_irqsave(&octeon_dev->fragment_lock, flags);
	cavium_list_for_each(tmp, &b->frags_list) {
		cavium_frag_buf_t *entry =
		    (cavium_frag_buf_t
		     *) (&(((cavium_frag_buf_t *) tmp)->list));
		if (entry->free_list_index < entry->frags_count) {
			index = entry->free_list[entry->free_list_index++];
			ret = entry->address[index];
			if (entry->not_allocated == 1) {
				entry->not_allocated = 0;
				cavium_list_add_tail(&entry->alloc_list,
						     &allocated_list_head);
			}
			break;
		}
	}
	cavium_spin_unlock_irqrestore(&octeon_dev->fragment_lock, flags);
	return ret;
}

/************************************************************* 
 * Function  : fragment_buffer
 *
 * Arguments : octeon_device_t *,  pool , uint8_t *
 * Returns   : void 
 *
 * This function fragments the buffer pointed to by "buf"
 * into sizes of b->chunk_size(of Pool p) and places the same 
 * into b->frag_list (of Pool p)
 * 
 *************************************************************/
static void
fragment_buffer(octeon_device_t * octeon_dev, OCTEON_BUFPOOL p, uint8_t * buf)
{
	buffer_tag *t =
	    (buffer_tag *) ((unsigned long)buf - sizeof(buffer_tag));
	cavium_frag_buf_t *fragment;
	uint16_t i;
	cavium_buffer_t *b = &(octeon_dev->buf[p]);
	unsigned long flags;

	cavium_spin_lock_irqsave(&octeon_dev->fragment_lock, flags);
	fragment = get_free_fragment(octeon_dev);

	fragment->big_buf = buf;

	switch (t->pool) {
	case ex_tiny:
		cavium_error
		    ("OCTEON: buffer pools fragmenting from tiny buffer\n");
		put_fragment(octeon_dev, *fragment);
		cavium_spin_unlock_irqrestore(&octeon_dev->fragment_lock,
					      flags);
		return;
	case tiny:
		fragment->frags_count =
		    (TINY_BUFFER_CHUNK_SIZE / b->chunk_size);
		break;
	case small:
		fragment->frags_count =
		    (SMALL_BUFFER_CHUNK_SIZE / b->chunk_size);
		break;
	case medium:
		fragment->frags_count =
		    (MEDIUM_BUFFER_CHUNK_SIZE / b->chunk_size);
		break;
	case large:
		fragment->frags_count =
		    (LARGE_BUFFER_CHUNK_SIZE / b->chunk_size);
		break;
	case huge:
		fragment->frags_count =
		    (HUGE_BUFFER_CHUNK_SIZE / b->chunk_size);
		break;
	default:
		/* bad, very bad! this should never happen. */
		cavium_error("OCTEON: Unsupported buffer pool %lu\n", t->pool);
		put_fragment(octeon_dev, *fragment);
		cavium_spin_unlock_irqrestore(&octeon_dev->fragment_lock,
					      flags);
		return;
	}

	fragment->p = p;
	fragment_buf_stats[p] += fragment->frags_count;

	for (i = 0; i < fragment->frags_count; i++) {
		fragment->free_list[i] = i;
		fragment->address[i] = buf + i * b->chunk_size;
	}
	fragment->free_list_index = 0;
	fragment->not_allocated = 1;
	cavium_list_add_tail(&fragment->list, &b->frags_list);
	cavium_spin_unlock_irqrestore(&octeon_dev->fragment_lock, flags);
}

/******************************************************
 * 
 * Function  : grow_buffers 
 *
 * Arguments : octeon_device_t *, pool 
 * Returns   : uint32_t 
 *
 * This function grows buffers in Pool p by allocating 
 * from higher pool and fragmenting the higher pool buffer
 *
 ******************************************************/
static uint32_t grow_buffers(octeon_device_t * octeon_dev, OCTEON_BUFPOOL p)
{
	uint8_t *buf = NULL;
	unsigned long flags;

	switch (p) {
	case ex_tiny:
		buf =
		    get_buffer_from_init_pool(octeon_dev,
					      &octeon_dev->buf[tiny]);
		if (buf) {
			other_pools[tiny]++;
			alloc_buffer_stats[tiny]++;
			break;
		}
	case tiny:
		buf =
		    get_buffer_from_init_pool(octeon_dev,
					      &octeon_dev->buf[small]);
		if (buf) {
			other_pools[small]++;
			alloc_buffer_stats[small]++;
			break;
		}
	case small:
		buf =
		    get_buffer_from_init_pool(octeon_dev,
					      &octeon_dev->buf[medium]);
		if (buf) {
			other_pools[medium]++;
			alloc_buffer_stats[medium]++;
			break;
		}
	case medium:
		buf =
		    get_buffer_from_init_pool(octeon_dev,
					      &octeon_dev->buf[large]);
		if (buf) {
			other_pools[large]++;
			alloc_buffer_stats[large]++;
			break;
		}
	case large:
		buf =
		    get_buffer_from_init_pool(octeon_dev,
					      &octeon_dev->buf[huge]);
		if (buf) {
			other_pools[huge]++;
			alloc_buffer_stats[huge]++;
			break;
		}
	case huge:
	case os:
		return 1;
	}

	if (buf) {
		int ret = 0;
		cavium_spin_lock_irqsave(&octeon_dev->fragment_lock, flags);
		if (octeon_dev->fragment_free_list_index == MAX_BUFFER_CHUNKS) {
			ret = 1;
		}
		cavium_spin_unlock_irqrestore(&octeon_dev->fragment_lock,
					      flags);
		if (ret) {
			put_buffer_in_pool(octeon_dev, buf);
			return 1;
		}
		fragment_buffer(octeon_dev, p, buf);
	}
	return 0;
}

/************************************************************
 * Function  : get_buffer_from_pool
 *
 * Arguments : void * , int 
 * Returns   : uint8_t *
 *
 * This function tries to get the requested buffer 
 * from the preallocated pool of buffers.If the preallocated
 * pool has exhausted, then it tries to grow the buffers 
 * from the next higher pool 
 * 
 *************************************************************/

uint8_t *get_buffer_from_pool(void *pdev, int size)
{
	octeon_device_t *octeon_dev = (octeon_device_t *) pdev;
	uint8_t *buf;
	OCTEON_BUFPOOL p;

get_buf:
	if (size <= EX_TINY_BUFFER_CHUNK_SIZE) {
		buf = get_buffer(octeon_dev, &octeon_dev->buf[ex_tiny]);
		p = ex_tiny;
	} else if (size <= TINY_BUFFER_CHUNK_SIZE) {
		buf = get_buffer(octeon_dev, &octeon_dev->buf[tiny]);
		p = tiny;
	} else if (size <= SMALL_BUFFER_CHUNK_SIZE) {
		buf = get_buffer(octeon_dev, &octeon_dev->buf[small]);
		p = small;
	} else if (size <= MEDIUM_BUFFER_CHUNK_SIZE) {
		buf = get_buffer(octeon_dev, &octeon_dev->buf[medium]);
		p = medium;
	} else if (size <= LARGE_BUFFER_CHUNK_SIZE) {
		buf = get_buffer(octeon_dev, &octeon_dev->buf[large]);
		p = large;
	} else if (size <= HUGE_BUFFER_CHUNK_SIZE) {
		buf = get_buffer(octeon_dev, &octeon_dev->buf[huge]);
		p = huge;
	} else {
		buf =
		    cavium_malloc_dma(size + sizeof(buffer_tag),
				      __CAVIUM_MEM_ATOMIC);
		if (buf) {
			((buffer_tag *) buf)->pool = os;
			((buffer_tag *) buf)->index = 0xffffdead;
			return (buf + sizeof(buffer_tag));
		} else {
			cavium_error
			    ("OCTEON: Out of memory get_buffer_from_pool %d\n",
			     size);
			return NULL;
		}
	}

	/* No Free buffers available */

	if (buf == NULL) {
		/* Try growing buffers */
		if (grow_buffers(octeon_dev, p)) {
			/* Unable to grow */
#ifdef CAVIUM_OS
			buf =
			    cavium_malloc_dma(size + sizeof(buffer_tag),
					      __CAVIUM_MEM_ATOMIC);
			if (buf) {
				((buffer_tag *) buf)->pool = os;
				return (buf + sizeof(buffer_tag));
			} else
#endif
			{
				cavium_error
				    ("OCTEON: Alloc failed (get_buffer_from_pool)\n");
				return buf;
			}
		}
		goto get_buf;
	}
	alloc_buffer_stats[p]++;
	return buf;
}

/*************************************************
 * Function : check_in_fragmented_pool
 *
 * Arguments    : octeon_device_t *, uint8_t *
 * Return Value : uint32_t 
 *
 * This function checks if a buffer is from a 
 * fragmented pool, and if so places the buffer 
 * on the free list
 *
 *************************************************/

static uint32_t
check_in_fragmented_pool(octeon_device_t * octeon_dev, uint8_t * b)
{
	cavium_list_t *tmp, *tmp1;
	unsigned long flags;

	cavium_spin_lock_irqsave(&octeon_dev->fragment_lock, flags);

	cavium_list_for_each_safe(tmp, tmp1, &allocated_list_head) {
		cavium_frag_buf_t *frag;
		uint16_t i;
		buffer_tag *t;

		frag =
		    (cavium_frag_buf_t
		     *) (&(((cavium_frag_buf_t *) tmp)->alloc_list));
		t = (buffer_tag *) ((unsigned long)(frag->big_buf) -
				    sizeof(buffer_tag));
		for (i = 0; i < frag->frags_count; i++) {
			if (frag->address[i] == b) {
				int big_buf_to_be_freed = 0;
				frag->free_list_index--;
				frag->free_list[frag->free_list_index] = i;
				alloc_buffer_stats[frag->p]--;
				if (frag->free_list_index == 0) {
					frag->not_allocated = 1;
					cavium_list_del(&frag->alloc_list);
					CAVIUM_INIT_LIST_HEAD
					    (&frag->alloc_list);
					/* Put back the big buffer */
					other_pools[t->pool]--;
					cavium_list_del(&frag->list);
					CAVIUM_INIT_LIST_HEAD(&frag->list);
					fragment_buf_stats[frag->p] -=
					    frag->frags_count;
					put_fragment(octeon_dev, *frag);
					big_buf_to_be_freed = 1;
				}
				cavium_spin_unlock_irqrestore
				    (&octeon_dev->fragment_lock, flags);
				if (big_buf_to_be_freed) {
					put_buffer(&octeon_dev->buf[t->pool],
						   t->index);
					alloc_buffer_stats[t->pool]--;
				}
				return 0;
			}
		}
	}
	cavium_spin_unlock_irqrestore(&octeon_dev->fragment_lock, flags);
	return 1;
}

/******************************************************** 
 *
 * Function : put_buffer_in_pool
 * 
 * Arguments     : void * , uint8_t * 
 * Return Value  : Returns void
 *
 * This function releases the buffer to the buffer pool
 * manager. 
 *
 ********************************************************/

void put_buffer_in_pool(void *dev, uint8_t * b)
{
	octeon_device_t *octeon_dev = (octeon_device_t *) dev;
	buffer_tag *t = NULL;

	t = (buffer_tag *) (b - sizeof(buffer_tag));
	if ((t->pool == os) && (t->index == 0xffffdead)) {
		cavium_free_dma((uint8_t *) t);
		return;
	}
	if (!check_in_fragmented_pool(octeon_dev, b)) {
		return;
	}

	switch (t->pool) {
	case ex_tiny:
		put_buffer(&octeon_dev->buf[ex_tiny], t->index);
		break;

	case tiny:
		put_buffer(&octeon_dev->buf[tiny], t->index);
		break;

	case small:
		put_buffer(&octeon_dev->buf[small], t->index);
		break;

	case medium:
		put_buffer(&octeon_dev->buf[medium], t->index);
		break;

	case large:
		put_buffer(&octeon_dev->buf[large], t->index);
		break;

	case huge:
		put_buffer(&octeon_dev->buf[huge], t->index);
		break;

	case os:
		cavium_free_dma((uint8_t *) t);
		break;
	default:
		/* bad, very bad! this should never happen. */
		cavium_error
		    ("OCTEON: Unsupported pool %lu in put_buffer_in_pool\n",
		     t->pool);
		return;
	}
	alloc_buffer_stats[t->pool]--;
}

void oct_get_buffer_pool_stats(oct_stats_t * stats)
{
	int i;

	stats->components |= OCTEON_BUFFER_POOL_STATS_ON;

	for (i = 0; i < BUF_POOLS; i++) {
		stats->bufpool[i].max_count = buffer_stats[i];
		stats->bufpool[i].alloc_count = alloc_buffer_stats[i];
		stats->bufpool[i].frag_count = fragment_buf_stats[i];
		stats->bufpool[i].other_pool_count = other_pools[i];
	}
}

#endif

/* $Id: buffer_pool.c 141410 2016-06-30 14:37:41Z mchalla $ */
