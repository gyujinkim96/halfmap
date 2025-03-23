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

#define DM_MSG_PREFIX "halfmap"

struct halfmap_c {
	struct dm_dev *dev;
};

struct dm_target_io {
    struct dm_target *ti;
    struct bio *orig_bio;
    atomic_t ref_count;
};

static int halfmap_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
    struct halfmap_c *hc;
    int ret;

    printk(KERN_ERR "halfmap_ctr init");
    if (argc != 1) {
        ti->error = "Invalid argument count. Expected 1 arguments for a nvme device";
        return -EINVAL;
    }
    
    hc = kmalloc(sizeof(*hc), GFP_KERNEL);
    if (hc == NULL) {
        ti->error = "Cannot allocate halfmap context";
        return -ENOMEM;
    }

    ret = dm_get_device(ti, argv[0], FMODE_READ | FMODE_WRITE, &hc->dev);
    if (ret) {
        ti->error = "Device lookup failed";
        return ret;
    }
    printk(KERN_ERR "halfmap_ctr done");
    ti->num_discard_bios = 0;
    ti->private = hc;
    return 0;
}

static void halfmap_dtr(struct dm_target *ti) {
    struct halfmap_c *hc = ti->private;

    dm_put_device(ti, hc->dev);
    kfree(hc);
}

static void halfmap_end_io(struct bio *cloned)
{
    struct dm_target_io *tio = cloned->bi_private;
    struct bio *orig_bio = tio->orig_bio;

    if (cloned->bi_status) {
        printk(KERN_ERR "cloned bio status: %d", cloned->bi_status);
        orig_bio->bi_status = cloned->bi_status;
    }

    bio_put(cloned);

    if (atomic_dec_and_test(&tio->ref_count)) {
        bio_endio(orig_bio);
        kfree(tio);
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

    tio = kmalloc(sizeof(*tio), GFP_KERNEL);
    if (tio == NULL) {
        return DM_MAPIO_KILL;
    }

    atomic_set(&tio->ref_count, 1);
    tio->ti = ti;
    tio->orig_bio = bio;

    clone = bio_alloc_clone(target_dev->bdev, bio, GFP_KERNEL, &fs_bio_set);
    if (clone == NULL) {
        kfree(tio);
        return DM_MAPIO_KILL;
    }

    clone->bi_private = tio;
    clone->bi_end_io = halfmap_end_io;

    atomic_inc(&tio->ref_count);
    submit_bio(clone);

    if (atomic_dec_and_test(&tio->ref_count)) {
        bio_endio(bio);
        kfree(tio);
    }

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

    printk(KERN_ERR "dm_halfmap_init");
    r = dm_register_target(&halfmap_target);

    if (r < 0)
        DMERR("register failed %d", r);

    return r;
}

static void __exit dm_halfmap_exit(void)
{
    printk(KERN_ERR "dm_halfmap_exit");
    dm_unregister_target(&halfmap_target);
}

module_init(dm_halfmap_init)
module_exit(dm_halfmap_exit)

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION("halfmap dummy target returning halfmaps");
MODULE_LICENSE("GPL");