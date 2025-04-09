/*
* Copyright (C) 2003 Jana Saout <jana@saout.de>
*
* This file is released under the GPL.
*/

#include <linux/device-mapper.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/types.h>
#include <linux/halfmap.h>
#include <asm/atomic.h>
#include <linux/minmax.h>

#define DM_MSG_PREFIX "halfmap"

#define HALFMAP_TEST

#ifdef HALFMAP_TEST
    #define SECTORS_PER_PAGE (8)
    #define SSD_CAPACITY (32 * 1024 * 1024 * 1024ULL)
    #define TOTAL_PHYSICAL_BLOCKS (8192 * 16)
    #define PAGES_PER_BLOCK (1024/16)
    #define ENTRY_SIZE (SSD_CAPACITY / 4096)
    #define INVALID_MAP (0xFFFFFFFF)
#else
    #define SECTORS_PER_PAGE (8)
    #define SSD_CAPACITY (32 * 1024 * 1024 * 1024ULL)
    #define TOTAL_PHYSICAL_BLOCKS (8192)
    #define PAGES_PER_BLOCK (1024)
    #define ENTRY_SIZE (SSD_CAPACITY / 4096)
    #define INVALID_MAP (0xFFFFFFFF)
#endif

#define SECTORS_PER_BLOCK ((PAGES_PER_BLOCK) * (SECTORS_PER_PAGE))

#define next_multiple(x, base) (round_down((x), (base)) + (base))

#define halfmap_debug(fmt, ...) do {           \
    if (show_splitted) {               \
        pr_info(fmt, ##__VA_ARGS__);   \
    }                                  \
} while (0)

static bool show_splitted = false;
module_param(show_splitted, bool, 0444);
MODULE_PARM_DESC(show_splitted, "Whether to show splitted address or not");

struct block_node {
    size_t idx;
    struct list_head list;
};

/*
   lock order: cur -> free + full
*/
struct block_manager {
    // new block + old block
    struct list_head free_blocks;
    struct list_head full_blocks;
    int current_block;
    size_t total_phys_blocks;
    int *write_count;

    spinlock_t cur_lock;
    spinlock_t free_lock;
    spinlock_t full_lock;
};


struct mapping {
    size_t max_entry;
    block_offset_t *map;
};


struct halfmap_c {
	struct dm_dev *dev;
    struct mapping *mapping;
    struct block_manager *blk_mgr;
};

struct dm_target_io {
    struct dm_target *ti;
    struct bio *orig_bio;
    atomic_t ref_count;
};

struct all_private {
    struct dm_target_io *shared;
    struct halfmap_private *private;
};

static void append_block_entry(struct list_head *list, block_offset_t block_id) {
    struct block_node *entry;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (entry == NULL) {
        pr_err("%s: failed to kmalloc block node: %d", __func__, block_id);
        return;
    }

    entry->idx = block_id;
    list_add_tail(&entry->list, list);
}

static void append_to_full_list(struct block_manager *bm, block_offset_t block_id) {
    spin_lock(&bm->full_lock);
    append_block_entry(&bm->full_blocks, block_id);
    spin_unlock(&bm->full_lock);
}

static struct mapping *mapping_alloc(size_t max_entry) {
    struct mapping *ret = NULL;
    int i;

    ret = kmalloc(sizeof(*ret), GFP_KERNEL);
    if (ret == NULL) {
        pr_err("%s: ret kmalloc failed", __func__);
        goto error;
    }

    ret->max_entry = max_entry;
    ret->map = kvmalloc(sizeof(*ret->map) * ret->max_entry, GFP_KERNEL);
    if (ret->map == NULL) {
        pr_err("%s: map vmalloc failed", __func__);
        goto error;
    }
    for (i = 0; i < ret->max_entry; i++) {
        ret->map[i] = INVALID_MAP;
    }

    return ret;

    error:
    kfree(ret);
    return NULL;
}

static void mapping_free(struct mapping *mp) {
    kvfree(mp->map);
    kfree(mp);
}

static struct block_manager *block_manager_alloc(size_t total_block_size) {
    struct block_manager *ret;
    int i;

    ret = kmalloc(sizeof(*ret), GFP_KERNEL);
    if (ret == NULL) {
        pr_err("%s kmalloc failed", __func__);
        return NULL;
    }

    ret->total_phys_blocks = total_block_size;
    ret->current_block = INVALID_MAP;

    INIT_LIST_HEAD(&ret->free_blocks);
    INIT_LIST_HEAD(&ret->full_blocks);

    for (i = 0; i < ret->total_phys_blocks; i++) {
        append_block_entry(&ret->free_blocks, i);
    }

    ret->write_count = kvmalloc(sizeof(*ret->write_count) * ret->total_phys_blocks, GFP_KERNEL);
    if (ret->write_count == NULL) {
        pr_err("%s write_count kvmalloc failed", __func__);
        kfree(ret);
        return NULL;
    }

    memset(ret->write_count, 0, sizeof(*ret->write_count) * ret->total_phys_blocks);

    spin_lock_init(&ret->free_lock);
    spin_lock_init(&ret->full_lock);
    spin_lock_init(&ret->cur_lock);

    return ret;
}

static void block_manager_free(struct block_manager *bm) {
    struct block_node *pos, *tmp;

    if (bm) {
        kvfree(bm->write_count);

        list_for_each_entry_safe(pos, tmp, &bm->free_blocks, list) {
            list_del(&pos->list);
            kfree(pos);
        }

        list_for_each_entry_safe(pos, tmp, &bm->full_blocks, list) {
            list_del(&pos->list);
            kfree(pos);
        }
    }

    kfree(bm);
}



static int alloc_block(struct block_manager *bm) {
    int ret = -1;
    struct block_node *node;

    spin_lock(&bm->free_lock);

    if (!list_empty(&bm->free_blocks)) {
        node = list_first_entry(&bm->free_blocks, struct block_node, list);
        list_del(&node->list);
        ret = node->idx;
        kfree(node);
    }
    
    spin_unlock(&bm->free_lock);

    return ret;
} 


static block_offset_t reserve_block(struct block_manager *bm, size_t start, size_t size, size_t *reserved_size) {
    block_offset_t current_block;
    size_t block_end;

    block_end = next_multiple(start, SECTORS_PER_BLOCK);

    size_t cur;

    
    spin_lock(&bm->cur_lock);
    
    if (bm->current_block == INVALID_MAP) {
        bm->current_block = alloc_block(bm);
    } 
    
    current_block = bm->current_block;
    if (current_block == INVALID_MAP) {
        pr_err("%s: failed to reserve free block", __func__);
        *reserved_size = 0;
    } else {
        size_t available;
        size_t page_needed;
        size_t start_page;
        size_t end_page;
        size_t page_using;

        start_page = start / SECTORS_PER_PAGE;
        end_page = (start + size -1) / SECTORS_PER_PAGE;
        page_needed = end_page - start_page + 1;
        available = min((size_t) PAGES_PER_BLOCK - bm->write_count[current_block], PAGES_PER_BLOCK - (start_page % PAGES_PER_BLOCK));
        cur = bm->write_count[current_block];
        
        if (available >= page_needed) {
            page_using = page_needed;
            *reserved_size = size;
        } else {
            page_using = available;
            *reserved_size = available * SECTORS_PER_PAGE;
        }
        
        bm->write_count[current_block] += page_using;
        
        if (bm->write_count[current_block] == PAGES_PER_BLOCK) {
            bm->current_block = INVALID_MAP;
            
            append_to_full_list(bm, current_block);
        }
    }
    
    spin_unlock(&bm->cur_lock);
    

    // pr_err("reserving: start=%zu size=%zu cur=%zu", start, size, cur);
    

    return current_block; 
}

static int halfmap_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct halfmap_c *hc = NULL;
    int ret;
    
    if (argc != 1) {
        ti->error = "Invalid argument count. Expected 1 arguments for a nvme device";
        ret = -EINVAL;
        goto error;
    }

    hc = kmalloc(sizeof(*hc), GFP_KERNEL);
    if (hc == NULL) {
        ti->error = "Cannot allocate halfmap context";
        ret = -ENOMEM;
        goto error;
    }

    memset(hc, 0, sizeof(*hc));
    hc->mapping = mapping_alloc(ENTRY_SIZE);
    if (hc->mapping == NULL) {
        ti->error = "Cannot allocate mapping";
        ret = -ENOMEM;
        goto error;
    }
   
    hc->blk_mgr = block_manager_alloc(TOTAL_PHYSICAL_BLOCKS);
    if (hc->blk_mgr == NULL) {
        ti->error = "Cannot allocate block manager";
        ret = -ENOMEM;
        goto error;
    }
   
    ret = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &hc->dev);
    if (ret) {
        ti->error = "Device lookup failed";
        ret = -ENOMEM;
        goto error;
    }

    ti->num_discard_bios = 0;
    ti->private = hc;
    return 0;

    error:
    if (hc) {
        kfree(hc->mapping);
        kfree(hc->blk_mgr);
        kfree(hc);
    }

    pr_err("%s: %s", __func__, ti->error);
    
    return -ENOMEM;
}

static void halfmap_dtr(struct dm_target *ti) {
    struct halfmap_c *hc = ti->private;

    dm_put_device(ti, hc->dev);

    block_manager_free(hc->blk_mgr);
    mapping_free(hc->mapping);
    kfree(hc);
}

static struct dm_target_io *alloc_tio(struct dm_target *ti, struct bio *bio) {
    struct dm_target_io *tio;

    tio = kmalloc(sizeof(*tio), GFP_KERNEL);
    if (tio == NULL) {
        return NULL;
    }

    atomic_set(&tio->ref_count, 1);
    tio->ti = ti;
    tio->orig_bio = bio;
    return tio;
}

static void decre_tio(struct dm_target_io *tio) {
    if (atomic_dec_and_test(&tio->ref_count)) {
        bio_endio(tio->orig_bio);
        kfree(tio);
    }
}

static void halfmap_end_io(struct bio *bio)
{
    struct all_private *ap = bio->bi_private;
    struct dm_target_io *tio = ap->shared;
    struct halfmap_private *pri = ap->private;
    struct halfmap_c *hc = tio->ti->private;

    bool is_writing;

    is_writing = bio_data_dir(bio) == WRITE;

    if (bio->bi_status) {
        pr_info("%s: orig bio status: %d => %d", __func__, tio->orig_bio->bi_status, bio->bi_status);
    }

    if (is_writing) {
        size_t start_page;
        size_t cur_page;
        size_t end_page;

        start_page = bio->bi_iter.bi_sector / SECTORS_PER_PAGE;
        end_page = (bio_end_sector(bio)-1) / SECTORS_PER_PAGE;
    
        for (cur_page = start_page; cur_page <= end_page; cur_page++) {
            hc->mapping->map[cur_page] = pri->new_blk_addr;
        }
    }


    kfree(pri);
    kfree(ap);

    bio_put(bio);

    decre_tio(tio);
}

static struct halfmap_private *private_for_write(struct halfmap_c *hc, size_t group_start, size_t group_size, size_t *reserved) {
    block_offset_t new_block;
    block_offset_t old_block;
    struct halfmap_private *pri;

    old_block = hc->mapping->map[group_start / SECTORS_PER_PAGE];

    // halfmap_debug("map idx: %zu", group_start / SECTORS_PER_PAGE);

    new_block = reserve_block(hc->blk_mgr, group_start, group_size, reserved);

    pri = kmalloc(sizeof(*pri), GFP_KERNEL);
    if (new_block == INVALID_MAP) {
        // what to do when there is no free page to write
        pr_err("%s: writing to invalid block", __func__);
        pri->new_blk_addr = new_block;
        pri->old_blk_addr = old_block;
    } else {
        pri->new_blk_addr = new_block;
        pri->old_blk_addr = old_block;
    }

    return pri;
}

static struct halfmap_private *private_for_read(struct halfmap_c *hc, size_t group_start, size_t group_size, size_t *reserved) {
    block_offset_t pbn;
    size_t block_end;
    size_t chunk_size;
    struct halfmap_private *pri;

    block_end = next_multiple(group_start, SECTORS_PER_BLOCK);

    

    pri = kmalloc(sizeof(*pri), GFP_KERNEL);

    pbn = hc->mapping->map[group_start / SECTORS_PER_PAGE];

    if (pbn == INVALID_MAP) {
        pri->new_blk_addr = INVALID_MAP;
        pri->old_blk_addr = INVALID_MAP;
        chunk_size = group_size;
    } else {
        pri->new_blk_addr = pbn;
        pri->old_blk_addr = INVALID_MAP;
        chunk_size = min(block_end - group_start, group_size);
    }

    *reserved = chunk_size;

    return pri;
}

static void submit_group(struct halfmap_c *hc, struct bio *bio, struct dm_target_io *tio, size_t group_start, size_t group_size) {
    struct all_private *ap;
    struct bio *split_bio;
    size_t reserved;
    struct halfmap_private *pri;
    bool is_writing;

    is_writing = bio_data_dir(bio) == WRITE;

    halfmap_debug("group start: %zu  size: %zu", group_start, group_size);

    while (group_size) {
        if (is_writing) {
            pri = private_for_write(hc, group_start, group_size, &reserved);
            halfmap_debug("from submit group: %s: %zu-%zu  new: %zu & old: %zu",
                 is_writing ? "writ" : "read", group_start, group_start+reserved,
                pri->new_blk_addr, pri->old_blk_addr);
        } else {
            pri = private_for_read(hc, group_start, group_size, &reserved);
            if (pri->new_blk_addr == INVALID_MAP) {
            split_bio = bio_next_split(bio, reserved, GFP_KERNEL, &fs_bio_set);
                zero_fill_bio(split_bio);
                bio_endio(split_bio);
                group_start += reserved;
                group_size -= reserved;
                continue;
            }
        }

        if (reserved == 0) {
            pr_err("%s: reserved is zero", __func__);
        }

        
        if (group_start / (SECTORS_PER_BLOCK) != (group_start + reserved - 1) / (SECTORS_PER_BLOCK)) {
            pr_err("BUG: group is written across different block. group_start=%zu, reserved=%zu, group_end=%zu, pages_per_block=%zu, sectors_per_page=%d\n",
                   group_start,
                   reserved,
                   group_start + reserved - 1,
                   PAGES_PER_BLOCK,
                   SECTORS_PER_PAGE);
            BUG();
        }
        
        ap = kmalloc(sizeof(*ap), GFP_KERNEL);
        ap->shared = tio;
        ap->private = pri;

        if (pri->new_blk_addr == INVALID_MAP) {
            pr_err("%s: pri cannot be null", __func__);
        }

        split_bio = bio_next_split(bio, reserved, GFP_KERNEL, &fs_bio_set);
        if (split_bio == NULL) {
                pr_err("%s: split bio is NULL", __func__);
        }

        split_bio->bi_private = ap;
        split_bio->bi_end_io = halfmap_end_io;
        
        atomic_inc(&tio->ref_count);
        submit_bio(split_bio);

        halfmap_debug("submit: %llu~%llu", split_bio->bi_iter.bi_sector, bio_end_sector(split_bio));
        
        group_start += reserved;
        group_size -= reserved;
    }
}


/*
* Return halfmaps only on reads
*/
static int halfmap_map(struct dm_target *ti, struct bio *bio)
{
	struct halfmap_c *hc = ti->private;
    struct dm_dev *target_dev = hc->dev;
    struct dm_target_io *tio;
    struct bio *clone;
    block_offset_t *map;

    size_t end_page;
    size_t cur_page;

    size_t start_sector;
    size_t end_sector;
    size_t end_sector_align;
    size_t total_sectors;

    size_t group_start;
    size_t group_start_page;
    
    tio = alloc_tio(ti, bio);
    if (tio == NULL) {
        return DM_MAPIO_KILL;
    }

    clone = bio_alloc_clone(target_dev->bdev, bio, GFP_KERNEL, &fs_bio_set);
    if (clone == NULL) {
        kfree(tio);
        return DM_MAPIO_KILL;
    }

    map = hc->mapping->map;


    end_page = next_multiple(bio_end_sector(clone), SECTORS_PER_PAGE) / SECTORS_PER_PAGE;

    start_sector = clone->bi_iter.bi_sector;
    end_sector = bio_end_sector(clone);
    end_sector_align = next_multiple(end_sector, SECTORS_PER_PAGE);

    group_start = start_sector;
    group_start_page = group_start / SECTORS_PER_PAGE;

    total_sectors = end_sector - start_sector;

    for (cur_page = group_start_page+1; cur_page <= end_page; cur_page++) {
        if (cur_page == end_page || map[group_start_page] != map[cur_page]) {
            size_t group_end;
            size_t group_size;

            if (cur_page * SECTORS_PER_PAGE <= end_sector) {
                group_end = cur_page * SECTORS_PER_PAGE;
            } else {
                group_end = end_sector;
            }

            group_size = group_end - group_start;
            submit_group(hc, clone, tio, group_start, group_size);

            group_start = cur_page * SECTORS_PER_PAGE;
            group_start_page = cur_page;
        }
    }

    decre_tio(tio);

    return DM_MAPIO_SUBMITTED;
}


static struct target_type halfmap_target = {
    .name   = "halfmap",
    .version = {1, 1, 0},
    .features = DM_TARGET_NOWAIT,
    .module = THIS_MODULE,
    .ctr    = halfmap_ctr,
    .dtr    = halfmap_dtr,
    .map    = halfmap_map,
};

static int __init dm_halfmap_init(void)
{
    int r = 0;

    pr_info("dm_halfmap_init");
    r = dm_register_target(&halfmap_target);

    if (r < 0)
        DMERR("register failed %d", r);

    return r;
}

static void __exit dm_halfmap_exit(void)
{
    pr_info("dm_halfmap_exit");
    dm_unregister_target(&halfmap_target);
}

module_init(dm_halfmap_init)
module_exit(dm_halfmap_exit)

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION("halfmap dummy target returning halfmaps");
MODULE_LICENSE("GPL");