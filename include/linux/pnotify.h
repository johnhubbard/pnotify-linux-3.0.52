#ifndef _LINUX_PNOTIFY_H
#define _LINUX_PNOTIFY_H

#include <linux/inotify.h>

struct pnotify_event {
	__s32		wd;		/* watch descriptor */
	__u32		mask;		/* watch mask */
	__u32		cookie;		/* cookie to synchronize two events */
	__u32		len;		/* length (including nulls) of name */
	__u32		tgid;		/* True process ID that made the file changes*/
	__u32		pid;		/* process ID (really, thread ID) that made the file changes*/
	__u32		ppid;		/* parent process of the pid*/
	__u64		jiffies;	/* timestamp when event was created*/
	unsigned long	inode_num;	/* inode number, if applicable */
	signed long	status;		/* event-dependent status */
	char		name[0];	/* Full path name */
};

#define PN_ANNOTATE		0x00100000      /* pnotify system: annotate event */
#define PN_PROCESS_CREATE	0x00200000      /* pnotify system: an observed process was created */
#define PN_PROCESS_EXIT 	0x00400000      /* pnotify system: an observed process exited */
#define PN_EXEC_CMD		0x00800000      /* pnotify system: an observed process called exec() */
#define PN_STAT		0x10000000      /* pnotify system: an observed process called ?stat() */

#define PN_ALL_EVENTS (IN_ALL_EVENTS | PN_ANNOTATE | PN_PROCESS_CREATE | PN_PROCESS_EXIT | PN_EXEC_CMD | PN_STAT)

#ifdef __KERNEL__
extern struct ctl_table pnotify_table[]; /* for sysctl */
int pnotify_broadcast_event(struct task_struct *task, u32 event_type, const char *msg);
#endif

#endif	/* _LINUX_PNOTIFY_H */
