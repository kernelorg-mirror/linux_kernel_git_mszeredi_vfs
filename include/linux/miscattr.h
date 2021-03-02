/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_MISCATTR_H
#define _LINUX_MISCATTR_H

/* Flags shared betwen flags/xflags */
#define FS_COMMON_FL \
	(FS_SYNC_FL | FS_IMMUTABLE_FL | FS_APPEND_FL | \
	 FS_NODUMP_FL |	FS_NOATIME_FL | FS_DAX_FL | \
	 FS_PROJINHERIT_FL)

#define FS_XFLAG_COMMON \
	(FS_XFLAG_SYNC | FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND | \
	 FS_XFLAG_NODUMP | FS_XFLAG_NOATIME | FS_XFLAG_DAX | \
	 FS_XFLAG_PROJINHERIT)

struct miscattr {
	u32	flags;		/* flags (FS_IOC_GETFLAGS/FS_IOC_SETFLAGS) */
	/* struct fsxattr: */
	u32	fsx_xflags;	/* xflags field value (get/set) */
	u32	fsx_extsize;	/* extsize field value (get/set)*/
	u32	fsx_nextents;	/* nextents field value (get)	*/
	u32	fsx_projid;	/* project identifier (get/set) */
	u32	fsx_cowextsize;	/* CoW extsize field value (get/set)*/
	/* selectors: */
	bool	flags_valid:1;
	bool	xattr_valid:1;
};

int fsxattr_copy_to_user(const struct miscattr *ma, struct fsxattr __user *ufa);

void miscattr_fill_xflags(struct miscattr *ma, u32 xflags);
void miscattr_fill_flags(struct miscattr *ma, u32 flags);

/**
 * miscattr_has_xattr - check for extentended flags/attributes
 * @ma:		miscattr pointer
 *
 * Returns true if any attributes are present that are not represented in
 * ->flags.
 */
static inline bool miscattr_has_xattr(const struct miscattr *ma)
{
	return ma->xattr_valid &&
		((ma->fsx_xflags & ~FS_XFLAG_COMMON) || ma->fsx_extsize != 0 ||
		 ma->fsx_projid != 0 ||	ma->fsx_cowextsize != 0);
}

int vfs_miscattr_get(struct dentry *dentry, struct miscattr *ma);
int vfs_miscattr_set(struct user_namespace *mnt_userns, struct dentry *dentry,
		     struct miscattr *ma);

#endif /* _LINUX_MISCATTR_H */
