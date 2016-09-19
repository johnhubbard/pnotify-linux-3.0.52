#include <linux/fsnotify_backend.h>
#include <linux/inotify.h>
#include <linux/slab.h> /* struct kmem_cache */

extern struct kmem_cache *pnotify_event_priv_cachep;
extern struct kmem_cache *pnotify_wd_pid_cachep __read_mostly;

struct pnotify_event_private_data {
	struct fsnotify_event_private_data fsnotify_event_priv_data;
	u32 wd;
};

struct pnotify_inode_mark {
	struct fsnotify_mark fsn_mark;
	u32 wd;
};

struct pnotify_wd_pid_struct {
	struct list_head pnotify_wd_pid_list_item;
	u32 wd;
	u32 pid;
};

extern void pnotify_ignored_and_remove_idr(struct fsnotify_mark *fsn_mark,
					   struct fsnotify_group *group);
extern void pnotify_free_event_priv(struct fsnotify_event_private_data *event_priv);

extern const struct fsnotify_ops pnotify_fsnotify_ops;
