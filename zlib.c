/**
 * Copyright (C) 2008 Oracle.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 * Based on jffs2 zlib code:
 * Copyright ? 2001-2007 Red Hat, Inc.
 * Created by David Woodhouse <dwmw2@infradead.org>
 */
 
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/zutil.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include "compression.h"
 

#define STREAM_END_SPACE 12

struct workspace {
    z_stream inf_strm;
    z_stream def_strm;
    char *buf;
    struct list_head list;
};
static LIST_HEAD(idle_workspace);
static DEFINE_SPINLOCK(workspace_lock);
static unsigned long num_workspace;
static atomic_t alloc_workspace = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(workspace_wait);
 
/**
 * this finds an available zlib workspace or allocates a new one
 * NULL or an ERR_PTR is returned if things go bad.
 */
static struct workspace *find_zlib_workspace(void)
{
    struct workspace *workspace;
    int ret;
    int cpus = num_online_cpus();
again:
    spin_lock(&workspace_lock);
    if (!list_empty(&idle_workspace)) {
        workspace = list_entry(idle_workspace.next, struct workspace,
                       list);
        list_del(&workspace->list);
        num_workspace--;
        spin_unlock(&workspace_lock);
        return workspace;
 
    }
    spin_unlock(&workspace_lock);
    if (atomic_read(&alloc_workspace) > cpus) {
        DEFINE_WAIT(wait);
        prepare_to_wait(&workspace_wait, &wait, TASK_UNINTERRUPTIBLE);
        if (atomic_read(&alloc_workspace) > cpus)
            schedule();
        finish_wait(&workspace_wait, &wait);
        goto again;
    }
    atomic_inc(&alloc_workspace);
    workspace = kzalloc(sizeof(*workspace), GFP_NOFS);
    if (!workspace) {
        ret = -ENOMEM;
        goto fail;
    }
 
    workspace->def_strm.workspace = vmalloc(zlib_deflate_workspacesize());
    if (!workspace->def_strm.workspace) {
        ret = -ENOMEM;
        goto fail;
    }
    workspace->inf_strm.workspace = vmalloc(zlib_inflate_workspacesize());
    if (!workspace->inf_strm.workspace) {
        ret = -ENOMEM;
        goto fail_inflate;
    }
    workspace->buf = kmalloc(PAGE_CACHE_SIZE, GFP_NOFS);
    if (!workspace->buf) {
        ret = -ENOMEM;
        goto fail_kmalloc;
    }
    return workspace;
 
fail_kmalloc:
    vfree(workspace->inf_strm.workspace);
fail_inflate:
    vfree(workspace->def_strm.workspace);
fail:
    kfree(workspace);
    atomic_dec(&alloc_workspace);
    wake_up(&workspace_wait);
    return ERR_PTR(ret);
}
 
/**
 * put a workspace struct back on the list or free it if we have enough
 * idle ones sitting around
 */
static int free_workspace(struct workspace *workspace)
{
    spin_lock(&workspace_lock);
    if (num_workspace < num_online_cpus()) {
        list_add_tail(&workspace->list, &idle_workspace);
        num_workspace++;
        spin_unlock(&workspace_lock);
        if (waitqueue_active(&workspace_wait))
            wake_up(&workspace_wait);
        return 0;
    }
    spin_unlock(&workspace_lock);
    vfree(workspace->def_strm.workspace);
    vfree(workspace->inf_strm.workspace);
    kfree(workspace->buf);
    kfree(workspace);
 
    atomic_dec(&alloc_workspace);
    if (waitqueue_active(&workspace_wait))
        wake_up(&workspace_wait);
    return 0;
}

 
/**
 * cleanup function for module exit
 */
static void free_workspaces(void)
{
    struct workspace *workspace;
    while (!list_empty(&idle_workspace)) {
        workspace = list_entry(idle_workspace.next, struct workspace,
                       list);
        list_del(&workspace->list);
        vfree(workspace->def_strm.workspace);
        vfree(workspace->inf_strm.workspace);
        kfree(workspace->buf);
        kfree(workspace);
        atomic_dec(&alloc_workspace);
    }
}
 
/**
 * given an address space and start/len, compress the bytes.
 *
 * pages are allocated to hold the compressed result and stored
 * in 'pages'
 *
 * out_pages is used to return the number of pages allocated.  There
 * may be pages allocated even if we return an error
 *
 * total_in is used to return the number of bytes actually read.  It
 * may be smaller then len if we had to exit early because we
 * ran out of room in the pages array or because we cross the
 * max_out threshold.
 *
 * total_out is used to return the total number of compressed bytes
 *
 * max_out tells us the max number of bytes that we're allowed to
 * stuff into pages
 */
int btrfs_zlib_compress_pages(struct address_space *mapping,
                  u64 start, unsigned long len,
                  struct page **pages,
                  unsigned long nr_dest_pages,
                  unsigned long *out_pages,
                  unsigned long *total_in,
                  unsigned long *total_out,
                  unsigned long max_out)
{
    int ret;
    struct workspace *workspace;
    char *data_in;
    char *cpage_out;
    int nr_pages = 0;
    struct page *in_page = NULL;
    struct page *out_page = NULL;
    unsigned long bytes_left;
 
    *out_pages = 0;
    *total_out = 0;
    *total_in = 0;
 
    workspace = find_zlib_workspace();
    if (IS_ERR(workspace))
        return -1;
 
    if (Z_OK != zlib_deflateInit(&workspace->def_strm, 3)) {
        printk(KERN_WARNING "deflateInit failed\n");
        ret = -1;
        goto out;
    }
 
    workspace->def_strm.total_in = 0;
    workspace->def_strm.total_out = 0;
 
    in_page = find_get_page(mapping, start >> PAGE_CACHE_SHIFT);
    data_in = kmap(in_page);
 
    out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
    cpage_out = kmap(out_page);
    pages[0] = out_page;
    nr_pages = 1;
 
    workspace->def_strm.next_in = data_in;
    workspace->def_strm.next_out = cpage_out;
    workspace->def_strm.avail_out = PAGE_CACHE_SIZE;
    workspace->def_strm.avail_in = min(len, PAGE_CACHE_SIZE);
 
    while (workspace->def_strm.total_in < len) {
        ret = zlib_deflate(&workspace->def_strm, Z_SYNC_FLUSH);
        if (ret != Z_OK) {
            printk(KERN_DEBUG "btrfs deflate in loop returned %d\n",
                   ret);
            zlib_deflateEnd(&workspace->def_strm);
            ret = -1;
            goto out;
        }
 
        /** we're making it bigger, give up */
        if (workspace->def_strm.total_in > 8192 &&
            workspace->def_strm.total_in <
            workspace->def_strm.total_out) {
            ret = -1;
            goto out;
        }
        /** we need another page for writing out.  Test this
         * before the total_in so we will pull in a new page for
         * the stream end if required
         */
        if (workspace->def_strm.avail_out == 0) {
            kunmap(out_page);
            if (nr_pages == nr_dest_pages) {
                out_page = NULL;
                ret = -1;
                goto out;
            }
            out_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
            cpage_out = kmap(out_page);
            pages[nr_pages] = out_page;
            nr_pages++;
            workspace->def_strm.avail_out = PAGE_CACHE_SIZE;
            workspace->def_strm.next_out = cpage_out;
        }
        /** we're all done */
        if (workspace->def_strm.total_in >= len)
            break;
 
        /** we've read in a full page, get a new one */
        if (workspace->def_strm.avail_in == 0) {
            if (workspace->def_strm.total_out > max_out)
                break;
 
            bytes_left = len - workspace->def_strm.total_in;
            kunmap(in_page);
            page_cache_release(in_page);
 
            start += PAGE_CACHE_SIZE;
            in_page = find_get_page(mapping,
                        start >> PAGE_CACHE_SHIFT);
            data_in = kmap(in_page);
            workspace->def_strm.avail_in = min(bytes_left,
                               PAGE_CACHE_SIZE);
            workspace->def_strm.next_in = data_in;
        }
    }
    workspace->def_strm.avail_in = 0;
    ret = zlib_deflate(&workspace->def_strm, Z_FINISH);
    zlib_deflateEnd(&workspace->def_strm);
 
    if (ret != Z_STREAM_END) {
        ret = -1;
        goto out;
    }
 
    if (workspace->def_strm.total_out >= workspace->def_strm.total_in) {
        ret = -1;
        goto out;
    }
 
    ret = 0;
    *total_out = workspace->def_strm.total_out;
    *total_in = workspace->def_strm.total_in;
out:
    *out_pages = nr_pages;
    if (out_page)
        kunmap(out_page);
 
    if (in_page) {
        kunmap(in_page);
        page_cache_release(in_page);
    }
    free_workspace(workspace);
    return ret;
}


