/*
 * pnotify_user.c - inotify support for userspace
 *
 * Authors:
 *	John McCutchan	<ttb@tentacle.dhs.org>
 *	Robert Love	<rml@novell.com>
 *
 * Copyright (C) 2005 John McCutchan
 * Copyright 2006 Hewlett-Packard Development Company, L.P.
 *
 * Copyright (C) 2009 Eric Paris <Red Hat Inc>
 * inotify was largely rewriten to make use of the fsnotify infrastructure
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 *  This is pnotify_user.c, which is a copy and modification of inotify_user.c
 *
 *  --John F. Hubbard <jhubbard@nvidia.com> 01 Dec 2011
 *
 */

#include <linux/file.h>
#include <linux/fs.h> /* struct inode */
#include <linux/fsnotify_backend.h>
#include <linux/idr.h>
#include <linux/init.h> /* module_init */
#include <linux/inotify.h>
#include <linux/pnotify.h>
#include <linux/kernel.h> /* roundup() */
#include <linux/namei.h> /* LOOKUP_FOLLOW */
#include <linux/sched.h> /* struct user */
#include <linux/slab.h> /* struct kmem_cache */
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/wait.h>

#include "pnotify.h"

#include <asm/ioctls.h>

extern rwlock_t tasklist_lock;

/* these are configurable via /proc/sys/fs/pnotify/ */
static int pnotify_max_user_instances __read_mostly;
static int pnotify_max_queued_events __read_mostly;
static int pnotify_max_user_watches __read_mostly;
static int pnotify_is_active __read_mostly;
static int pnotify_is_active_boot_arg;
static int pnotify_arg_needs_update = 0;

int pnotify_debug_print_level __read_mostly;
static int pnotify_major_version __read_mostly;
static int pnotify_minor_version __read_mostly;

struct kmem_cache *pnotify_inode_mark_cachep __read_mostly;
struct kmem_cache *pnotify_event_priv_cachep __read_mostly;
struct kmem_cache *pnotify_wd_pid_cachep __read_mostly;

static struct mutex pnotify_annotate_mutex;

#ifdef CONFIG_SYSCTL

#include <linux/sysctl.h>

static int zero;

ctl_table pnotify_table[] = {
	{
		.procname	= "max_user_instances",
		.data		= &pnotify_max_user_instances,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
	},
	{
		.procname	= "max_user_watches",
		.data		= &pnotify_max_user_watches,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
	},
	{
		.procname	= "max_queued_events",
		.data		= &pnotify_max_queued_events,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero
	},
	{
		.procname	= "is_active",
		.data		= &pnotify_is_active,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero
	},
	{
		.procname	= "debug_print_level",
		.data		= &pnotify_debug_print_level,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero
	},
	{
		.procname	= "major_version",
		.data		= &pnotify_major_version,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero
	},
	{
		.procname	= "minor_version",
		.data		= &pnotify_minor_version,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero
	},
	{ }
};
#endif /* CONFIG_SYSCTL */

static inline __u32 pnotify_arg_to_mask(u32 arg)
{
	__u32 mask;

	/*
	 * everything should accept their own ignored, cares about children,
	 * and should receive events when the inode is unmounted
	 */
	mask = (FS_IN_IGNORED | FS_EVENT_ON_CHILD | FS_UNMOUNT);

	/* mask off the flags used to open the fd */
	mask |= (arg & (PN_ALL_EVENTS | IN_ONESHOT | IN_EXCL_UNLINK));

	return mask;
}

u32 pnotify_mask_to_arg(__u32 mask)
{
	return mask & (PN_ALL_EVENTS | IN_ISDIR | IN_UNMOUNT | IN_IGNORED |
		       IN_Q_OVERFLOW);
}

/* intofiy userspace file descriptor functions */
static unsigned int pnotify_poll(struct file *file, poll_table *wait)
{
	struct fsnotify_group *group = file->private_data;
	int ret = 0;

	poll_wait(file, &group->notification_waitq, wait);
	mutex_lock(&group->notification_mutex);
	if (!fsnotify_notify_queue_is_empty(group))
		ret = POLLIN | POLLRDNORM;
	mutex_unlock(&group->notification_mutex);

	return ret;
}

/*
 * Get a pnotify_kernel_event if one exists and is small
 * enough to fit in "count". Return an error pointer if
 * not large enough.
 *
 * Called with the group->notification_mutex held.
 */
static
struct fsnotify_event *pnotify_get_one_event(struct fsnotify_group *group,
					     size_t count)
{
	size_t event_size = sizeof(struct pnotify_event);
	struct fsnotify_event *event;

	if (fsnotify_notify_queue_is_empty(group))
		return NULL;

	event = fsnotify_peek_notify_event(group);

	pr_debug("%s: group=%p event=%p\n", __func__, group, event);

	if (event->name_len)
		event_size += roundup(event->name_len + 1, event_size);

	if (event_size > count)
		return ERR_PTR(-EINVAL);

	/* held the notification_mutex the whole time, so this is the
	 * same event we peeked above */
	fsnotify_remove_notify_event(group);

	return event;
}

/*
 * Copy an event to user space, returning how much we copied.
 *
 * We already checked that the event size is smaller than the
 * buffer we had in "get_one_event()" above.
 */
static ssize_t pnotify_copy_event_to_user(struct fsnotify_group *group,
					  struct fsnotify_event *event,
					  char __user *buf)
{
	struct pnotify_event pnotify_event;
	struct fsnotify_event_private_data *fsn_priv;
	struct pnotify_event_private_data *priv;
	size_t event_size = sizeof(struct pnotify_event);
	size_t name_len = 0;

	pr_debug("%s: group=%p event=%p\n", __func__, group, event);

	/* we get the pnotify watch descriptor from the event private data */
	spin_lock(&event->lock);
	fsn_priv = fsnotify_remove_priv_from_event(group, event);
	spin_unlock(&event->lock);

	if (!fsn_priv) {
		pnotify_event.wd = -1;
		pnotify_event.pid = 0;
		pnotify_event.ppid = 0;
	} else {
		priv = container_of(fsn_priv, struct pnotify_event_private_data,
				    fsnotify_event_priv_data);
		pnotify_event.wd = priv->wd;
		pnotify_free_event_priv(fsn_priv);
	}

	/*
	 * round up event->name_len so it is a multiple of event_size
	 * plus an extra byte for the terminating '\0'.
	 */
	if (event->name_len)
		name_len = roundup(event->name_len + 1, event_size);
	pnotify_event.len = name_len;

	pnotify_event.mask = pnotify_mask_to_arg(event->mask);
	pnotify_event.cookie = event->sync_cookie;
	pnotify_event.pid = event->event_pid;
	pnotify_event.ppid = event->event_ppid;
	pnotify_event.tgid = event->event_tgid;
	pnotify_event.jiffies = event->event_jiffies;
	pnotify_event.inode_num = event->event_inode_num;
	pnotify_event.status = event->event_status;

	/* send the main event */
	if (copy_to_user(buf, &pnotify_event, event_size))
		return -EFAULT;

	buf += event_size;

	/*
	 * fsnotify only stores pathname, so here we have to send the pathname
	 * and then pad that pathname out to a multiple of sizeof(pnotify_event)
	 * with zeros.  I get my zeros from the nul_pnotify_event.
	 */
	if (name_len) {
		unsigned int len_to_zero = name_len - event->name_len;
		/* copy the path name */
		if (copy_to_user(buf, event->file_name, event->name_len))
			return -EFAULT;
		buf += event->name_len;

		/* fill userspace with 0's */
		if (clear_user(buf, len_to_zero))
			return -EFAULT;
		buf += len_to_zero;
		event_size += name_len;
	}

	return event_size;
}

static ssize_t pnotify_read(struct file *file, char __user *buf,
			    size_t count, loff_t *pos)
{
	struct fsnotify_group *group;
	struct fsnotify_event *kevent;
	char __user *start;
	int ret;
	DEFINE_WAIT(wait);

	start = buf;
	group = file->private_data;

	while (1) {
		prepare_to_wait(&group->notification_waitq, &wait,
				TASK_INTERRUPTIBLE);

		mutex_lock(&group->notification_mutex);
		kevent = pnotify_get_one_event(group, count);
		mutex_unlock(&group->notification_mutex);

		pr_debug("%s: group=%p kevent=%p\n", __func__, group, kevent);

		if (kevent) {
			ret = PTR_ERR(kevent);
			if (IS_ERR(kevent))
				break;
			ret = pnotify_copy_event_to_user(group, kevent, buf);
			fsnotify_put_event(kevent);
			if (ret < 0)
				break;
			buf += ret;
			count -= ret;
			continue;
		}

		ret = -EAGAIN;
		if (file->f_flags & O_NONBLOCK)
			break;
		ret = -EINTR;
		if (signal_pending(current))
			break;

		if (start != buf)
			break;

		schedule();
	}

	finish_wait(&group->notification_waitq, &wait);
	if (start != buf && ret != -EFAULT)
		ret = buf - start;
	return ret;
}

static int pnotify_fasync(int fd, struct file *file, int on)
{
	struct fsnotify_group *group = file->private_data;

	return fasync_helper(fd, file, on,
			     &group->pnotify_data.fa) >= 0 ? 0 : -EIO;
}

static int pnotify_release(struct inode *ignored, struct file *file)
{
	struct fsnotify_group *group = file->private_data;

	pr_debug("%s: group=%p\n", __func__, group);

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: group=0x%p\n", __func__, group);

	fsnotify_clear_marks_by_group(group);

	/* free this group, matching get was
	   pnotify_init->fsnotify_obtain_group */
	fsnotify_put_group(group);

	return 0;
}

static long pnotify_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct fsnotify_group *group;
	struct fsnotify_event_holder *holder;
	struct fsnotify_event *event;
	void __user *p;
	int ret = -ENOTTY;
	size_t send_len = 0;

	group = file->private_data;
	p = (void __user *) arg;

	pr_debug("%s: group=%p cmd=%u\n", __func__, group, cmd);
	pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
		      "%s: group=%p cmd=%u\n", __func__, group, cmd);

	switch (cmd) {
	case FIONREAD:
		mutex_lock(&group->notification_mutex);
		list_for_each_entry(holder, &group->notification_list,
				    event_list) {
			event = holder->event;
			send_len += sizeof(struct pnotify_event);
			if (event->name_len)
				send_len += roundup(event->name_len + 1,
						sizeof(struct pnotify_event));
		}
		mutex_unlock(&group->notification_mutex);
		ret = put_user(send_len, (int __user *) p);
		break;
	}

	return ret;
}

static const struct file_operations pnotify_fops = {
	.poll		= pnotify_poll,
	.read		= pnotify_read,
	.fasync		= pnotify_fasync,
	.release	= pnotify_release,
	.unlocked_ioctl	= pnotify_ioctl,
	.compat_ioctl	= pnotify_ioctl,
	.llseek		= noop_llseek,
};


static int pnotify_add_to_idr(struct idr *idr, spinlock_t *idr_lock,
			      int *last_wd,
			      struct pnotify_inode_mark *i_mark)
{
	int ret;

	do {
		if (unlikely(!idr_pre_get(idr, GFP_KERNEL)))
			return -ENOMEM;

		spin_lock(idr_lock);
		ret = idr_get_new_above(idr, i_mark, *last_wd + 1,
					&i_mark->wd);
		/* we added the mark to the idr, take a reference */
		if (!ret) {
			*last_wd = i_mark->wd;
			fsnotify_get_mark(&i_mark->fsn_mark);
		}
		spin_unlock(idr_lock);
	} while (ret == -EAGAIN);

	return ret;
}

static
struct pnotify_inode_mark *pnotify_idr_find_locked(struct fsnotify_group *group,
						   int wd)
{
	struct idr *idr = &group->pnotify_data.idr;
	spinlock_t *idr_lock = &group->pnotify_data.idr_lock;
	struct pnotify_inode_mark *i_mark;

	assert_spin_locked(idr_lock);

	i_mark = idr_find(idr, wd);
	if (i_mark) {
		struct fsnotify_mark *fsn_mark = &i_mark->fsn_mark;

		fsnotify_get_mark(fsn_mark);
		/* One ref for being in the idr, one ref we just took */
		BUG_ON(atomic_read(&fsn_mark->refcnt) < 2);
	}

	return i_mark;
}

static struct pnotify_inode_mark *pnotify_idr_find(struct fsnotify_group *group,
						   int wd)
{
	struct pnotify_inode_mark *i_mark;
	spinlock_t *idr_lock = &group->pnotify_data.idr_lock;

	spin_lock(idr_lock);
	i_mark = pnotify_idr_find_locked(group, wd);
	spin_unlock(idr_lock);

	return i_mark;
}

static void do_pnotify_remove_from_idr(struct fsnotify_group *group,
				       struct pnotify_inode_mark *i_mark)
{
	struct idr *idr = &group->pnotify_data.idr;
	spinlock_t *idr_lock = &group->pnotify_data.idr_lock;
	int wd = i_mark->wd;

	assert_spin_locked(idr_lock);

	idr_remove(idr, wd);

	/* removed from the idr, drop that ref */
	fsnotify_put_mark(&i_mark->fsn_mark);
}

/*
 * Remove the mark from the idr (if present) and drop the reference
 * on the mark because it was in the idr.
 */
static void pnotify_remove_from_idr(struct fsnotify_group *group,
				    struct pnotify_inode_mark *i_mark)
{
	spinlock_t *idr_lock = &group->pnotify_data.idr_lock;
	struct pnotify_inode_mark *found_i_mark = NULL;
	int wd;

	spin_lock(idr_lock);
	wd = i_mark->wd;

	/*
	 * does this i_mark think it is in the idr?  we shouldn't get called
	 * if it wasn't....
	 */
	if (wd == -1) {
		WARN_ONCE(1, "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p"
			" i_mark->inode=%p\n", __func__, i_mark, i_mark->wd,
			i_mark->fsn_mark.group, i_mark->fsn_mark.i.inode);
		goto out;
	}

	/* Lets look in the idr to see if we find it */
	found_i_mark = pnotify_idr_find_locked(group, wd);
	if (unlikely(!found_i_mark)) {
		WARN_ONCE(1, "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p"
			" i_mark->inode=%p\n", __func__, i_mark, i_mark->wd,
			i_mark->fsn_mark.group, i_mark->fsn_mark.i.inode);
		goto out;
	}

	/*
	 * We found an mark in the idr at the right wd, but it's
	 * not the mark we were told to remove.  eparis seriously
	 * fucked up somewhere.
	 */
	if (unlikely(found_i_mark != i_mark)) {
		WARN_ONCE(1, "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p "
			"mark->task=%p found_i_mark=%p found_i_mark->wd=%d "
			"found_i_mark->group=%p found_i_mark->inode=%p\n",
			__func__, i_mark, i_mark->wd, i_mark->fsn_mark.group,
			i_mark->fsn_mark.t.task, found_i_mark, found_i_mark->wd,
			found_i_mark->fsn_mark.group,
			found_i_mark->fsn_mark.t.task);
		goto out;
	}

	/*
	 * One ref for being in the idr
	 * one ref held by the caller trying to kill us
	 * one ref grabbed by pnotify_idr_find
	 */
	if (unlikely(atomic_read(&i_mark->fsn_mark.refcnt) < 3)) {
		printk(KERN_ERR "%s: i_mark=%p i_mark->wd=%d i_mark->group=%p"
			" i_mark->inode=%p\n", __func__, i_mark, i_mark->wd,
			i_mark->fsn_mark.group, i_mark->fsn_mark.t.task);
		/* we can't really recover with bad ref cnting.. */
		BUG();
	}

	do_pnotify_remove_from_idr(group, i_mark);
out:
	/* match the ref taken by pnotify_idr_find_locked() */
	if (found_i_mark)
		fsnotify_put_mark(&found_i_mark->fsn_mark);
	i_mark->wd = -1;
	spin_unlock(idr_lock);
}

/*
 * Send IN_IGNORED for this wd, remove this wd from the idr.
 */
void pnotify_ignored_and_remove_idr(struct fsnotify_mark *fsn_mark,
				    struct fsnotify_group *group)
{
	struct pnotify_inode_mark *i_mark;
	struct fsnotify_event *ignored_event, *notify_event;
	struct pnotify_event_private_data *event_priv;
	struct fsnotify_event_private_data *fsn_event_priv;
	int ret;

	ignored_event = fsnotify_create_event(NULL, FS_IN_IGNORED, NULL,
					      FSNOTIFY_EVENT_NONE, NULL, 0,
					      GFP_NOFS, 0, 0, 0, NULL, 0);
	if (!ignored_event)
		return;

	i_mark = container_of(fsn_mark, struct pnotify_inode_mark, fsn_mark);

	event_priv = kmem_cache_alloc(pnotify_event_priv_cachep, GFP_NOFS);
	if (unlikely(!event_priv))
		goto skip_send_ignore;

	fsn_event_priv = &event_priv->fsnotify_event_priv_data;

	fsn_event_priv->group = group;
	event_priv->wd = i_mark->wd;

	notify_event = fsnotify_add_notify_event(group, ignored_event, fsn_event_priv, NULL);
	if (notify_event) {
		if (IS_ERR(notify_event))
			ret = PTR_ERR(notify_event);
		else
			fsnotify_put_event(notify_event);
		pnotify_free_event_priv(fsn_event_priv);
	}

skip_send_ignore:

	/* matches the reference taken when the event was created */
	fsnotify_put_event(ignored_event);

	/* remove this mark from the idr */
	pnotify_remove_from_idr(group, i_mark);

	atomic_dec(&group->pnotify_data.user->pnotify_watches);
}

/* ding dong the mark is dead */
static void pnotify_free_mark(struct fsnotify_mark *fsn_mark)
{
	struct pnotify_inode_mark *i_mark;

	i_mark = container_of(fsn_mark, struct pnotify_inode_mark, fsn_mark);

	kmem_cache_free(pnotify_inode_mark_cachep, i_mark);
}

int pnotify_create_process_event(struct task_struct *task,
				 struct fsnotify_mark *fsn_mark,
				 struct fsnotify_group *group,
				 u32 event_type,
				 char *msg)
{
	struct pnotify_inode_mark *i_mark;
	struct fsnotify_event *special_event, *notify_event;
	struct pnotify_event_private_data *event_priv;
	struct fsnotify_event_private_data *fsn_event_priv;
	int ret = 0;

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: Entering: group: 0x%p, event_type: %u\n",
		      __func__, group, event_type);

	special_event = fsnotify_create_event(NULL, event_type, NULL,
					      FSNOTIFY_EVENT_NONE, msg, 0,
					      GFP_NOFS,
					      task->tgid,
					      task->pid,
					      task->parent ? task->parent->pid : 0,
					      NULL,
					      PN_PROCESS_EXIT != event_type ? 0 : task->exit_code);
	if (!special_event)
		return -ENOENT; /* This return value is a little arbitrary */

	i_mark = container_of(fsn_mark, struct pnotify_inode_mark, fsn_mark);

	event_priv = kmem_cache_alloc(pnotify_event_priv_cachep, GFP_NOFS);
	if (unlikely(!event_priv)) {
		ret = -ENOMEM;
		goto skip_send_ignore;
	}

	fsn_event_priv = &event_priv->fsnotify_event_priv_data;

	fsn_event_priv->group = group;
	event_priv->wd = i_mark->wd;

	notify_event = fsnotify_add_notify_event(group, special_event, fsn_event_priv, NULL);
	if (notify_event) {
		if (IS_ERR(notify_event))
			ret = PTR_ERR(notify_event);
		else
			fsnotify_put_event(notify_event);
		pnotify_free_event_priv(fsn_event_priv);
	}

skip_send_ignore:

	/* matches the reference taken when the event was created */
	fsnotify_put_event(special_event);

	return ret;
}

int pnotify_create_annotate_event(struct task_struct *task,
                                  struct fsnotify_mark *fsn_mark,
				  struct fsnotify_group *group, char *msg)
{
	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: Entering: group: 0x%p, msg: %s\n",
		      __func__, group, msg);

	return pnotify_create_process_event(task, fsn_mark, group,
					    PN_ANNOTATE, msg);
}

int pnotify_create_process_create_event(struct task_struct *task,
					struct fsnotify_mark *fsn_mark,
					struct fsnotify_group *group)
{
	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: Entering: group: 0x%p, pid: %u\n",
		      __func__, group, task->pid);

	return pnotify_create_process_event(task, fsn_mark, group,
					    PN_PROCESS_CREATE, NULL);
}

int pnotify_create_process_exit_event(struct task_struct *task,
				      struct fsnotify_mark *fsn_mark,
				      struct fsnotify_group *group)
{
	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: Entering: group: 0x%p, pid: %u\n",
		      __func__, group, task->pid);

	return pnotify_create_process_event(task, fsn_mark, group,
					    PN_PROCESS_EXIT, NULL);
}

/*
 * Given an task, send a PN_ANNOTATE to each observer of that task.
 */
int pnotify_broadcast_annotate(struct task_struct *task, char *msg)
{
	struct fsnotify_mark *mark, *lmark;
	struct hlist_node *pos, *n;
	int ret = -ENOENT;
	int lastret = 0;
	LIST_HEAD(bcast_list);

	mutex_lock(&pnotify_annotate_mutex);

	task_lock(task);
	hlist_for_each_entry_safe(mark, pos, n, &task->pnotify_marks,
				  t.t_list) {
		list_add(&mark->t.bcast_t_list, &bcast_list);
		fsnotify_get_mark(mark); // due to bcast_list copy
	}
	task_unlock(task);

	list_for_each_entry_safe(mark, lmark, &bcast_list, t.bcast_t_list) {
		pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
			      "%s: Sending message (%s) to observer/mark: 0x%p"
			      " (mark->mask:"
			      " 0x%x) for task->pid: %u\n",
			      __func__, msg, mark, mark->mask, task->pid);

		/* Just record the last error, if any, for the return value: */
		lastret = pnotify_create_annotate_event(task, mark,
							mark->group, msg);
		if (lastret)
			ret = lastret;
		list_del_init(&mark->t.bcast_t_list);
		fsnotify_put_mark(mark); // due to bcast_list copy
	}

	BUG_ON(!list_empty(&bcast_list));

	mutex_unlock(&pnotify_annotate_mutex);
	return ret;
}

static int pnotify_update_existing_watch(struct fsnotify_group *group,
					 u32 pid,
					 u32 arg)
{
	struct fsnotify_mark *fsn_mark;
	struct pnotify_inode_mark *p_mark;
	__u32 old_mask, new_mask;
	__u32 mask;
	int add = (arg & IN_MASK_ADD);
	int ret;
	struct task_struct *task;

	/* don't allow invalid bits: we don't want flags set */
	mask = pnotify_arg_to_mask(arg);
	if (unlikely(!(mask & PN_ALL_EVENTS)))
		return -EINVAL;

	rcu_read_lock();
	task = find_task_by_pid_ns(pid, &init_pid_ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task) {
		pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
			      "%s: FAILED to add watch on pid %u\n",
			      __func__, pid);
		ret = -ESRCH;
		goto failed_out;
	}

	fsn_mark = fsnotify_find_task_mark(group, task);
	if (!fsn_mark) {
		ret = -ENOENT;
        goto failed_out;
    }

	p_mark = container_of(fsn_mark, struct pnotify_inode_mark, fsn_mark);

	spin_lock(&fsn_mark->lock);

	old_mask = fsn_mark->mask;
	if (add)
		fsnotify_set_mark_mask_locked(fsn_mark, (fsn_mark->mask|mask));
	else
		fsnotify_set_mark_mask_locked(fsn_mark, mask);
	new_mask = fsn_mark->mask;

	spin_unlock(&fsn_mark->lock);

	if (old_mask != new_mask) {
		/* more bits in old than in new? */
		int dropped = (old_mask & ~new_mask);
		/* more bits in this fsn_mark than the task's mask? */
		int do_task = (new_mask & ~task->pnotify_mask);

		/* update the inode with this new fsn_mark */
		if (dropped || do_task)
			fsnotify_recalc_task_mask(task);
	}

	/* return the wd */
	ret = p_mark->wd;

	/* match the get from fsnotify_find_mark() */
	fsnotify_put_mark(fsn_mark);
failed_out:
	if (task)
		put_task_struct(task);

	return ret;
}

int pnotify_get_wd(struct fsnotify_group *group, u32 pid)
{
	struct pnotify_wd_pid_struct *pos;

	spin_lock(&group->pnotify_data.wd_pid_lock);

	list_for_each_entry(pos, &group->pnotify_data.wd_pid_list,
			    pnotify_wd_pid_list_item) {
		if (pos->pid == pid) {
			spin_unlock(&group->pnotify_data.wd_pid_lock);
			return pos->wd;
		}
	}
	spin_unlock(&group->pnotify_data.wd_pid_lock);

	return -1; /* failed to find a wd for this pid */
}

static int add_wd_pid_pair(struct fsnotify_group *group, int wd, u32 pid)
{
	struct pnotify_wd_pid_struct *pos, *new;

	spin_lock(&group->pnotify_data.wd_pid_lock);

	list_for_each_entry(pos, &group->pnotify_data.wd_pid_list,
			    pnotify_wd_pid_list_item) {
		if (pos->pid == pid && pos->wd == wd) {
			spin_unlock(&group->pnotify_data.wd_pid_lock);
			return 0; /* already have an entry */
		}
	}
	spin_unlock(&group->pnotify_data.wd_pid_lock);

	new = kmem_cache_alloc(pnotify_wd_pid_cachep, GFP_KERNEL);
	if (unlikely(!new))
		return -ENOMEM;

	new->wd = wd;
	new->pid = pid;

	spin_lock(&group->pnotify_data.wd_pid_lock);
	list_add_tail(&new->pnotify_wd_pid_list_item,
		      &group->pnotify_data.wd_pid_list);
	spin_unlock(&group->pnotify_data.wd_pid_lock);

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: added pair: wd=%d, pid=%u\n", __func__, wd, pid);
	return 0;
}

int pnotify_perm_check(u32 pid)
{
	int ret = 0;
	struct task_struct *task;

#ifndef CONFIG_PNOTIFY_USER
	return -ENOENT;
#endif
	if (!pnotify_is_active)
		return -ENOENT;

	rcu_read_lock();
	task = find_task_by_pid_ns(pid, &init_pid_ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task) {
		pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
			      "%s: FAILED to find pid %u\n", __func__, pid);
		ret = -ESRCH;
		goto out_err;
	}

	/* Fortunately, the permissions for pnotify are conceptually
	 * identical to those required for ptrace, so we can reuse that
	 * function call:
	 */
	if (!ptrace_may_access(task, PTRACE_MODE_READ))
		ret = -EPERM;

	put_task_struct(task);
out_err:
	return ret;
}

int pnotify_new_watch(struct fsnotify_group *group, u32 pid, u32 arg)
{
	struct pnotify_inode_mark *tmp_i_mark;
	__u32 mask;
	int ret;
	struct idr *idr = &group->pnotify_data.idr;
	spinlock_t *idr_lock = &group->pnotify_data.idr_lock;
	struct task_struct *task = NULL;

	/* don't allow invalid bits: we don't want flags set */
	mask = pnotify_arg_to_mask(arg);
	if (unlikely(!(mask & PN_ALL_EVENTS)))
		return -EINVAL;

	tmp_i_mark = kmem_cache_alloc(pnotify_inode_mark_cachep, GFP_KERNEL);
	if (unlikely(!tmp_i_mark))
		return -ENOMEM;

	fsnotify_init_mark(&tmp_i_mark->fsn_mark, pnotify_free_mark);
	tmp_i_mark->fsn_mark.mask = mask;
	tmp_i_mark->wd = -1;

	ret = -ENOSPC;
	if (atomic_read(&group->pnotify_data.user->pnotify_watches) >=
			pnotify_max_user_watches)
		goto out_err;

	ret = pnotify_add_to_idr(idr, idr_lock, &group->pnotify_data.last_wd,
				 tmp_i_mark);
	if (ret)
		goto out_err;

	rcu_read_lock();
	task = find_task_by_pid_ns(pid, &init_pid_ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task) {
		pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
			      "%s: FAILED to add watch on pid %u\n",
			      __func__, pid);
		ret = -ESRCH;
		goto out_err;
	}

	/* we are on the idr, now get on the task */
	ret = fsnotify_add_mark(&tmp_i_mark->fsn_mark, group,
				NULL, NULL, task, 0);
	if (ret) {
		/* we failed to get on the inode, get off the idr */
		pnotify_remove_from_idr(group, tmp_i_mark);
		goto out_err;
	}

	/* increment the number of watches the user has */
	atomic_inc(&group->pnotify_data.user->pnotify_watches);

	ret = add_wd_pid_pair(group, tmp_i_mark->wd, pid);
	if (ret)
		goto out_err;

	/* return the watch descriptor for this new mark */
	ret = tmp_i_mark->wd;

out_err:
    if (task)
        put_task_struct(task);

	/* match the ref from fsnotify_init_mark() */
	fsnotify_put_mark(&tmp_i_mark->fsn_mark);
	return ret;
}

static int pnotify_update_watch(struct fsnotify_group *group, u32 pid, u32 arg)
{
	int ret = 0;

retry:
	/* try to update and existing watch with the new arg */
	ret = pnotify_update_existing_watch(group, pid, arg);
	/* no mark present, try to add a new one */
	if (ret == -ENOENT)
		ret = pnotify_new_watch(group, pid, arg);
	/*
	 * pnotify_new_watch could race with another thread which did an
	 * pnotify_new_watch between the update_existing and the add watch
	 * here, go back and try to update an existing mark again.
	 */
	if (ret == -EEXIST)
		goto retry;

	return ret;
}

static struct fsnotify_group *pnotify_new_group(unsigned int max_events)
{
	struct fsnotify_group *group;

	group = fsnotify_alloc_group(&pnotify_fsnotify_ops);
	if (IS_ERR(group))
		return group;

	group->max_events = max_events;

	spin_lock_init(&group->pnotify_data.idr_lock);
	idr_init(&group->pnotify_data.idr);
	group->pnotify_data.last_wd = 0;
	group->pnotify_data.fa = NULL;
	group->pnotify_data.user = get_current_user();

	spin_lock_init(&group->pnotify_data.wd_pid_lock);
	INIT_LIST_HEAD(&group->pnotify_data.wd_pid_list);

	if (atomic_inc_return(&group->pnotify_data.user->pnotify_devs) >
	    pnotify_max_user_instances) {
		fsnotify_put_group(group);
		return ERR_PTR(-EMFILE);
	}

	return group;
}

/* For the user's convenience, the pnotify system API allows the calling code
 * to pass in an event_fd and a pid. However, internally, pnotify uses the wd,
 * in order to use as much inotify and fsnotify code as possible. Therefore,
 * a list of wd,pid pairs is attached to the events_fs, to allow looking up
 * the wd, given pid.
 */

/* pnotify syscalls */
SYSCALL_DEFINE0(pnotify_init)
{
	struct fsnotify_group *group;
	int ret;

#ifndef CONFIG_PNOTIFY_USER
	return -ENOENT;
#endif
	if (!pnotify_is_active)
		return -ENOENT;

	/* fsnotify_obtain_group took a reference to group, we put this when
	   we kill the file in the end */
	group = pnotify_new_group(pnotify_max_queued_events);
	if (IS_ERR(group))
		return PTR_ERR(group);

	ret = anon_inode_getfd("pnotify", &pnotify_fops, group,
				  O_RDONLY);
	if (ret < 0)
		fsnotify_put_group(group);

	INIT_LIST_HEAD(&group->pnotify_data.wd_pid_list);

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
		      "%s: events_fd: %d, group: 0x%p\n",
		      __func__, ret, group);
	return ret;
}

SYSCALL_DEFINE4(pnotify_add_watch, int, events_fd, u32, pid, u32, mask,
		u32, flags)
{
	struct fsnotify_group *group;
	struct file *filp;
	int ret, fput_needed;

	ret = pnotify_perm_check(pid);
	if (ret)
		return ret;

	filp = fget_light(events_fd, &fput_needed);
	if (unlikely(!filp))
		return -EBADF;

	/* verify that this is really a pnotify instance */
	if (unlikely(filp->f_op != &pnotify_fops)) {
		ret = -EINVAL;
		goto fput_and_out;
	}

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
		      "%s: events_fd: %d, mask: 0x%x, flags: 0x%x, pid: %u\n",
		      __func__, events_fd, mask, flags, pid);

	/* group is held in place by fget on fd */
	group = filp->private_data;

	/* create/update an inode mark */
	ret = pnotify_update_watch(group, pid, mask);
fput_and_out:
	fput_light(filp, fput_needed);
	return ret;
}

SYSCALL_DEFINE2(pnotify_rm_watch, int, events_fd, u32, pid)
{
	struct fsnotify_group *group;
	struct pnotify_inode_mark *i_mark;
	struct file *filp;
	int ret = 0, fput_needed;
	int wd;

	ret = pnotify_perm_check(pid);
	if (ret)
		return ret;

	filp = fget_light(events_fd, &fput_needed);
	if (unlikely(!filp))
		return -EBADF;

	/* verify that this is indeed an pnotify instance */
	ret = -EINVAL;
	if (unlikely(filp->f_op != &pnotify_fops))
		goto out;

	group = filp->private_data;

	ret = -EINVAL;

	wd = pnotify_get_wd(group, pid);

	i_mark = pnotify_idr_find(group, wd);
	if (unlikely(!i_mark))
		goto out;

	ret = 0;

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: Preparing: events_fd: %d, pid: %u (wd: %d)\n",
		      __func__, events_fd, pid, wd);
	fsnotify_destroy_mark(&i_mark->fsn_mark);

	/* match ref taken by pnotify_idr_find */
	fsnotify_put_mark(&i_mark->fsn_mark);

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
		      "%s: Done: events_fd: %d, pid: %u (wd: %d)\n",
		      __func__, events_fd, pid, wd);

out:
	fput_light(filp, fput_needed);
	return ret;
}

SYSCALL_DEFINE3(pnotify_annotate, u32, pid, const char __user *, buf, u32, len)
{
	int ret;
	char *kernel_buf = NULL;
	struct task_struct *task = NULL;

	ret = pnotify_perm_check(pid);
	if (ret)
		return ret;

	if (len > (PAGE_SIZE - sizeof(struct pnotify_event) - 1))
		return -EINVAL;

	rcu_read_lock();
	task = find_task_by_pid_ns(pid, &init_pid_ns);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task) {
		pnotify_debug(PNOTIFY_DEBUG_LEVEL_MINIMAL,
			      "%s: FAILED to find pid %u\n",
			      __func__, pid);
		ret = -ESRCH;
		goto out;
	}

	kernel_buf = (char *) __get_free_page(GFP_KERNEL);
	if (!kernel_buf) {
		ret = -ENOMEM;
		goto out;
	}

	memset(kernel_buf, 0, PAGE_SIZE);
	ret = _copy_from_user(kernel_buf, buf, len);
	if (ret != 0) {
		ret = -EINVAL;
		goto out;
	}

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
		      "%s: Preparing: pid: %u, msg: %s\n",
		      __func__, pid, kernel_buf);

	ret = pnotify_broadcast_annotate(task, kernel_buf);
out:
	if (task)
		put_task_struct(task);
	if (kernel_buf)
		free_page((unsigned long) kernel_buf);

	return ret;
}

/*
 * pnotify_user_setup - Our initialization function.  Note that we cannot return
 * error because we have compiled-in VFS hooks.  So an (unlikely) failure here
 * must result in panic().
 */
static int __init pnotify_user_setup(void)
{
	pnotify_inode_mark_cachep = KMEM_CACHE(pnotify_inode_mark, SLAB_PANIC);
	pnotify_event_priv_cachep = KMEM_CACHE(pnotify_event_private_data,
					       SLAB_PANIC);
	pnotify_wd_pid_cachep = KMEM_CACHE(pnotify_wd_pid_struct, SLAB_PANIC);

	mutex_init(&pnotify_annotate_mutex);

	pnotify_max_queued_events = 1024 * 1024;
	pnotify_max_user_instances = 128;
	pnotify_max_user_watches = 8192;

	if (pnotify_arg_needs_update)
		pnotify_is_active = pnotify_is_active_boot_arg;
	else
		pnotify_is_active = 1;

	pnotify_debug_print_level = 0;
	pnotify_major_version = 1;
	pnotify_minor_version = 2;

	return 0;
}
module_init(pnotify_user_setup);

/* Enables pnotify, if non-zero. Default: 1.
 * Sets /proc/sys/fs/pnotify/is_active :
 */
static int __init pnotify_is_active_setup(char *str)
{
	pnotify_is_active_boot_arg = simple_strtol(str, NULL, 0);
	pnotify_arg_needs_update = 1;
	return 1;
}
__setup("pnotify_is_active=", pnotify_is_active_setup);
