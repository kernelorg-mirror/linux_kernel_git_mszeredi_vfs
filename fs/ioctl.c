// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ioctl.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/uaccess.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <linux/falloc.h>
#include <linux/sched/signal.h>
#include <linux/fiemap.h>
#include <linux/mount.h>
#include <linux/fscrypt.h>
#include <linux/miscattr.h>

#include "internal.h"

#include <asm/ioctls.h>

/* So that the fiemap access checks can't overflow on 32 bit machines. */
#define FIEMAP_MAX_EXTENTS	(UINT_MAX / sizeof(struct fiemap_extent))

/**
 * vfs_ioctl - call filesystem specific ioctl methods
 * @filp:	open file to invoke ioctl method on
 * @cmd:	ioctl command to execute
 * @arg:	command-specific argument for ioctl
 *
 * Invokes filesystem specific ->unlocked_ioctl, if one exists; otherwise
 * returns -ENOTTY.
 *
 * Returns 0 on success, -errno on error.
 */
long vfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int error = -ENOTTY;

	if (!filp->f_op->unlocked_ioctl)
		goto out;

	error = filp->f_op->unlocked_ioctl(filp, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;
 out:
	return error;
}
EXPORT_SYMBOL(vfs_ioctl);

static int ioctl_fibmap(struct file *filp, int __user *p)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	int error, ur_block;
	sector_t block;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	error = get_user(ur_block, p);
	if (error)
		return error;

	if (ur_block < 0)
		return -EINVAL;

	block = ur_block;
	error = bmap(inode, &block);

	if (block > INT_MAX) {
		error = -ERANGE;
		pr_warn_ratelimited("[%s/%d] FS: %s File: %pD4 would truncate fibmap result\n",
				    current->comm, task_pid_nr(current),
				    sb->s_id, filp);
	}

	if (error)
		ur_block = 0;
	else
		ur_block = block;

	if (put_user(ur_block, p))
		error = -EFAULT;

	return error;
}

/**
 * fiemap_fill_next_extent - Fiemap helper function
 * @fieinfo:	Fiemap context passed into ->fiemap
 * @logical:	Extent logical start offset, in bytes
 * @phys:	Extent physical start offset, in bytes
 * @len:	Extent length, in bytes
 * @flags:	FIEMAP_EXTENT flags that describe this extent
 *
 * Called from file system ->fiemap callback. Will populate extent
 * info as passed in via arguments and copy to user memory. On
 * success, extent count on fieinfo is incremented.
 *
 * Returns 0 on success, -errno on error, 1 if this was the last
 * extent that will fit in user array.
 */
#define SET_UNKNOWN_FLAGS	(FIEMAP_EXTENT_DELALLOC)
#define SET_NO_UNMOUNTED_IO_FLAGS	(FIEMAP_EXTENT_DATA_ENCRYPTED)
#define SET_NOT_ALIGNED_FLAGS	(FIEMAP_EXTENT_DATA_TAIL|FIEMAP_EXTENT_DATA_INLINE)
int fiemap_fill_next_extent(struct fiemap_extent_info *fieinfo, u64 logical,
			    u64 phys, u64 len, u32 flags)
{
	struct fiemap_extent extent;
	struct fiemap_extent __user *dest = fieinfo->fi_extents_start;

	/* only count the extents */
	if (fieinfo->fi_extents_max == 0) {
		fieinfo->fi_extents_mapped++;
		return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
	}

	if (fieinfo->fi_extents_mapped >= fieinfo->fi_extents_max)
		return 1;

	if (flags & SET_UNKNOWN_FLAGS)
		flags |= FIEMAP_EXTENT_UNKNOWN;
	if (flags & SET_NO_UNMOUNTED_IO_FLAGS)
		flags |= FIEMAP_EXTENT_ENCODED;
	if (flags & SET_NOT_ALIGNED_FLAGS)
		flags |= FIEMAP_EXTENT_NOT_ALIGNED;

	memset(&extent, 0, sizeof(extent));
	extent.fe_logical = logical;
	extent.fe_physical = phys;
	extent.fe_length = len;
	extent.fe_flags = flags;

	dest += fieinfo->fi_extents_mapped;
	if (copy_to_user(dest, &extent, sizeof(extent)))
		return -EFAULT;

	fieinfo->fi_extents_mapped++;
	if (fieinfo->fi_extents_mapped == fieinfo->fi_extents_max)
		return 1;
	return (flags & FIEMAP_EXTENT_LAST) ? 1 : 0;
}
EXPORT_SYMBOL(fiemap_fill_next_extent);

/**
 * fiemap_prep - check validity of requested flags for fiemap
 * @inode:	Inode to operate on
 * @fieinfo:	Fiemap context passed into ->fiemap
 * @start:	Start of the mapped range
 * @len:	Length of the mapped range, can be truncated by this function.
 * @supported_flags:	Set of fiemap flags that the file system understands
 *
 * This function must be called from each ->fiemap instance to validate the
 * fiemap request against the file system parameters.
 *
 * Returns 0 on success, or a negative error on failure.
 */
int fiemap_prep(struct inode *inode, struct fiemap_extent_info *fieinfo,
		u64 start, u64 *len, u32 supported_flags)
{
	u64 maxbytes = inode->i_sb->s_maxbytes;
	u32 incompat_flags;
	int ret = 0;

	if (*len == 0)
		return -EINVAL;
	if (start > maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (*len > maxbytes || (maxbytes - *len) < start)
		*len = maxbytes - start;

	supported_flags |= FIEMAP_FLAG_SYNC;
	supported_flags &= FIEMAP_FLAGS_COMPAT;
	incompat_flags = fieinfo->fi_flags & ~supported_flags;
	if (incompat_flags) {
		fieinfo->fi_flags = incompat_flags;
		return -EBADR;
	}

	if (fieinfo->fi_flags & FIEMAP_FLAG_SYNC)
		ret = filemap_write_and_wait(inode->i_mapping);
	return ret;
}
EXPORT_SYMBOL(fiemap_prep);

static int ioctl_fiemap(struct file *filp, struct fiemap __user *ufiemap)
{
	struct fiemap fiemap;
	struct fiemap_extent_info fieinfo = { 0, };
	struct inode *inode = file_inode(filp);
	int error;

	if (!inode->i_op->fiemap)
		return -EOPNOTSUPP;

	if (copy_from_user(&fiemap, ufiemap, sizeof(fiemap)))
		return -EFAULT;

	if (fiemap.fm_extent_count > FIEMAP_MAX_EXTENTS)
		return -EINVAL;

	fieinfo.fi_flags = fiemap.fm_flags;
	fieinfo.fi_extents_max = fiemap.fm_extent_count;
	fieinfo.fi_extents_start = ufiemap->fm_extents;

	error = inode->i_op->fiemap(inode, &fieinfo, fiemap.fm_start,
			fiemap.fm_length);

	fiemap.fm_flags = fieinfo.fi_flags;
	fiemap.fm_mapped_extents = fieinfo.fi_extents_mapped;
	if (copy_to_user(ufiemap, &fiemap, sizeof(fiemap)))
		error = -EFAULT;

	return error;
}

static long ioctl_file_clone(struct file *dst_file, unsigned long srcfd,
			     u64 off, u64 olen, u64 destoff)
{
	struct fd src_file = fdget(srcfd);
	loff_t cloned;
	int ret;

	if (!src_file.file)
		return -EBADF;
	ret = -EXDEV;
	if (src_file.file->f_path.mnt != dst_file->f_path.mnt)
		goto fdput;
	cloned = vfs_clone_file_range(src_file.file, off, dst_file, destoff,
				      olen, 0);
	if (cloned < 0)
		ret = cloned;
	else if (olen && cloned != olen)
		ret = -EINVAL;
	else
		ret = 0;
fdput:
	fdput(src_file);
	return ret;
}

static long ioctl_file_clone_range(struct file *file,
				   struct file_clone_range __user *argp)
{
	struct file_clone_range args;

	if (copy_from_user(&args, argp, sizeof(args)))
		return -EFAULT;
	return ioctl_file_clone(file, args.src_fd, args.src_offset,
				args.src_length, args.dest_offset);
}

#ifdef CONFIG_BLOCK

static inline sector_t logical_to_blk(struct inode *inode, loff_t offset)
{
	return (offset >> inode->i_blkbits);
}

static inline loff_t blk_to_logical(struct inode *inode, sector_t blk)
{
	return (blk << inode->i_blkbits);
}

/**
 * __generic_block_fiemap - FIEMAP for block based inodes (no locking)
 * @inode: the inode to map
 * @fieinfo: the fiemap info struct that will be passed back to userspace
 * @start: where to start mapping in the inode
 * @len: how much space to map
 * @get_block: the fs's get_block function
 *
 * This does FIEMAP for block based inodes.  Basically it will just loop
 * through get_block until we hit the number of extents we want to map, or we
 * go past the end of the file and hit a hole.
 *
 * If it is possible to have data blocks beyond a hole past @inode->i_size, then
 * please do not use this function, it will stop at the first unmapped block
 * beyond i_size.
 *
 * If you use this function directly, you need to do your own locking. Use
 * generic_block_fiemap if you want the locking done for you.
 */
static int __generic_block_fiemap(struct inode *inode,
			   struct fiemap_extent_info *fieinfo, loff_t start,
			   loff_t len, get_block_t *get_block)
{
	struct buffer_head map_bh;
	sector_t start_blk, last_blk;
	loff_t isize = i_size_read(inode);
	u64 logical = 0, phys = 0, size = 0;
	u32 flags = FIEMAP_EXTENT_MERGED;
	bool past_eof = false, whole_file = false;
	int ret = 0;

	ret = fiemap_prep(inode, fieinfo, start, &len, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	/*
	 * Either the i_mutex or other appropriate locking needs to be held
	 * since we expect isize to not change at all through the duration of
	 * this call.
	 */
	if (len >= isize) {
		whole_file = true;
		len = isize;
	}

	/*
	 * Some filesystems can't deal with being asked to map less than
	 * blocksize, so make sure our len is at least block length.
	 */
	if (logical_to_blk(inode, len) == 0)
		len = blk_to_logical(inode, 1);

	start_blk = logical_to_blk(inode, start);
	last_blk = logical_to_blk(inode, start + len - 1);

	do {
		/*
		 * we set b_size to the total size we want so it will map as
		 * many contiguous blocks as possible at once
		 */
		memset(&map_bh, 0, sizeof(struct buffer_head));
		map_bh.b_size = len;

		ret = get_block(inode, start_blk, &map_bh, 0);
		if (ret)
			break;

		/* HOLE */
		if (!buffer_mapped(&map_bh)) {
			start_blk++;

			/*
			 * We want to handle the case where there is an
			 * allocated block at the front of the file, and then
			 * nothing but holes up to the end of the file properly,
			 * to make sure that extent at the front gets properly
			 * marked with FIEMAP_EXTENT_LAST
			 */
			if (!past_eof &&
			    blk_to_logical(inode, start_blk) >= isize)
				past_eof = 1;

			/*
			 * First hole after going past the EOF, this is our
			 * last extent
			 */
			if (past_eof && size) {
				flags = FIEMAP_EXTENT_MERGED|FIEMAP_EXTENT_LAST;
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
			} else if (size) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size, flags);
				size = 0;
			}

			/* if we have holes up to/past EOF then we're done */
			if (start_blk > last_blk || past_eof || ret)
				break;
		} else {
			/*
			 * We have gone over the length of what we wanted to
			 * map, and it wasn't the entire file, so add the extent
			 * we got last time and exit.
			 *
			 * This is for the case where say we want to map all the
			 * way up to the second to the last block in a file, but
			 * the last block is a hole, making the second to last
			 * block FIEMAP_EXTENT_LAST.  In this case we want to
			 * see if there is a hole after the second to last block
			 * so we can mark it properly.  If we found data after
			 * we exceeded the length we were requesting, then we
			 * are good to go, just add the extent to the fieinfo
			 * and break
			 */
			if (start_blk > last_blk && !whole_file) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
				break;
			}

			/*
			 * if size != 0 then we know we already have an extent
			 * to add, so add it.
			 */
			if (size) {
				ret = fiemap_fill_next_extent(fieinfo, logical,
							      phys, size,
							      flags);
				if (ret)
					break;
			}

			logical = blk_to_logical(inode, start_blk);
			phys = blk_to_logical(inode, map_bh.b_blocknr);
			size = map_bh.b_size;
			flags = FIEMAP_EXTENT_MERGED;

			start_blk += logical_to_blk(inode, size);

			/*
			 * If we are past the EOF, then we need to make sure as
			 * soon as we find a hole that the last extent we found
			 * is marked with FIEMAP_EXTENT_LAST
			 */
			if (!past_eof && logical + size >= isize)
				past_eof = true;
		}
		cond_resched();
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

	} while (1);

	/* If ret is 1 then we just hit the end of the extent array */
	if (ret == 1)
		ret = 0;

	return ret;
}

/**
 * generic_block_fiemap - FIEMAP for block based inodes
 * @inode: The inode to map
 * @fieinfo: The mapping information
 * @start: The initial block to map
 * @len: The length of the extect to attempt to map
 * @get_block: The block mapping function for the fs
 *
 * Calls __generic_block_fiemap to map the inode, after taking
 * the inode's mutex lock.
 */

int generic_block_fiemap(struct inode *inode,
			 struct fiemap_extent_info *fieinfo, u64 start,
			 u64 len, get_block_t *get_block)
{
	int ret;
	inode_lock(inode);
	ret = __generic_block_fiemap(inode, fieinfo, start, len, get_block);
	inode_unlock(inode);
	return ret;
}
EXPORT_SYMBOL(generic_block_fiemap);

#endif  /*  CONFIG_BLOCK  */

/*
 * This provides compatibility with legacy XFS pre-allocation ioctls
 * which predate the fallocate syscall.
 *
 * Only the l_start, l_len and l_whence fields of the 'struct space_resv'
 * are used here, rest are ignored.
 */
static int ioctl_preallocate(struct file *filp, int mode, void __user *argp)
{
	struct inode *inode = file_inode(filp);
	struct space_resv sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += filp->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(filp, mode | FALLOC_FL_KEEP_SIZE, sr.l_start,
			sr.l_len);
}

/* on ia32 l_start is on a 32-bit boundary */
#if defined CONFIG_COMPAT && defined(CONFIG_X86_64)
/* just account for different alignment */
static int compat_ioctl_preallocate(struct file *file, int mode,
				    struct space_resv_32 __user *argp)
{
	struct inode *inode = file_inode(file);
	struct space_resv_32 sr;

	if (copy_from_user(&sr, argp, sizeof(sr)))
		return -EFAULT;

	switch (sr.l_whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		sr.l_start += file->f_pos;
		break;
	case SEEK_END:
		sr.l_start += i_size_read(inode);
		break;
	default:
		return -EINVAL;
	}

	return vfs_fallocate(file, mode | FALLOC_FL_KEEP_SIZE, sr.l_start, sr.l_len);
}
#endif

static int file_ioctl(struct file *filp, unsigned int cmd, int __user *p)
{
	switch (cmd) {
	case FIBMAP:
		return ioctl_fibmap(filp, p);
	case FS_IOC_RESVSP:
	case FS_IOC_RESVSP64:
		return ioctl_preallocate(filp, 0, p);
	case FS_IOC_UNRESVSP:
	case FS_IOC_UNRESVSP64:
		return ioctl_preallocate(filp, FALLOC_FL_PUNCH_HOLE, p);
	case FS_IOC_ZERO_RANGE:
		return ioctl_preallocate(filp, FALLOC_FL_ZERO_RANGE, p);
	}

	return -ENOIOCTLCMD;
}

static int ioctl_fionbio(struct file *filp, int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = O_NONBLOCK;
#ifdef __sparc__
	/* SunOS compatibility item. */
	if (O_NONBLOCK != O_NDELAY)
		flag |= O_NDELAY;
#endif
	spin_lock(&filp->f_lock);
	if (on)
		filp->f_flags |= flag;
	else
		filp->f_flags &= ~flag;
	spin_unlock(&filp->f_lock);
	return error;
}

static int ioctl_fioasync(unsigned int fd, struct file *filp,
			  int __user *argp)
{
	unsigned int flag;
	int on, error;

	error = get_user(on, argp);
	if (error)
		return error;
	flag = on ? FASYNC : 0;

	/* Did FASYNC state change ? */
	if ((flag ^ filp->f_flags) & FASYNC) {
		if (filp->f_op->fasync)
			/* fasync() adjusts filp->f_flags */
			error = filp->f_op->fasync(fd, filp, on);
		else
			error = -ENOTTY;
	}
	return error < 0 ? error : 0;
}

static int ioctl_fsfreeze(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!ns_capable(sb->s_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/* If filesystem doesn't support freeze feature, return. */
	if (sb->s_op->freeze_fs == NULL && sb->s_op->freeze_super == NULL)
		return -EOPNOTSUPP;

	/* Freeze */
	if (sb->s_op->freeze_super)
		return sb->s_op->freeze_super(sb);
	return freeze_super(sb);
}

static int ioctl_fsthaw(struct file *filp)
{
	struct super_block *sb = file_inode(filp)->i_sb;

	if (!ns_capable(sb->s_user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	/* Thaw */
	if (sb->s_op->thaw_super)
		return sb->s_op->thaw_super(sb);
	return thaw_super(sb);
}

static int ioctl_file_dedupe_range(struct file *file,
				   struct file_dedupe_range __user *argp)
{
	struct file_dedupe_range *same = NULL;
	int ret;
	unsigned long size;
	u16 count;

	if (get_user(count, &argp->dest_count)) {
		ret = -EFAULT;
		goto out;
	}

	size = offsetof(struct file_dedupe_range __user, info[count]);
	if (size > PAGE_SIZE) {
		ret = -ENOMEM;
		goto out;
	}

	same = memdup_user(argp, size);
	if (IS_ERR(same)) {
		ret = PTR_ERR(same);
		same = NULL;
		goto out;
	}

	same->dest_count = count;
	ret = vfs_dedupe_file_range(file, same);
	if (ret)
		goto out;

	ret = copy_to_user(argp, same, size);
	if (ret)
		ret = -EFAULT;

out:
	kfree(same);
	return ret;
}

/**
 * miscattr_fill_xflags - initialize miscattr with xflags
 * @ma:		miscattr pointer
 * @xflags:	FS_XFLAG_* flags
 *
 * Set ->fsx_xflags, ->xattr_valid and ->flags (translated xflags).  All
 * other fields are zeroed.
 */
void miscattr_fill_xflags(struct miscattr *ma, u32 xflags)
{
	memset(ma, 0, sizeof(*ma));
	ma->xattr_valid = true;
	ma->fsx_xflags = xflags;
	if (ma->fsx_xflags & FS_XFLAG_IMMUTABLE)
		ma->flags |= FS_IMMUTABLE_FL;
	if (ma->fsx_xflags & FS_XFLAG_APPEND)
		ma->flags |= FS_APPEND_FL;
	if (ma->fsx_xflags & FS_XFLAG_SYNC)
		ma->flags |= FS_SYNC_FL;
	if (ma->fsx_xflags & FS_XFLAG_NOATIME)
		ma->flags |= FS_NOATIME_FL;
	if (ma->fsx_xflags & FS_XFLAG_NODUMP)
		ma->flags |= FS_NODUMP_FL;
	if (ma->fsx_xflags & FS_XFLAG_DAX)
		ma->flags |= FS_DAX_FL;
	if (ma->fsx_xflags & FS_XFLAG_PROJINHERIT)
		ma->flags |= FS_PROJINHERIT_FL;
}
EXPORT_SYMBOL(miscattr_fill_xflags);

/**
 * miscattr_fill_flags - initialize miscattr with flags
 * @ma:		miscattr pointer
 * @flags:	FS_*_FL flags
 *
 * Set ->flags, ->flags_valid and ->fsx_xflags (translated flags).
 * All other fields are zeroed.
 */
void miscattr_fill_flags(struct miscattr *ma, u32 flags)
{
	memset(ma, 0, sizeof(*ma));
	ma->flags_valid = true;
	ma->flags = flags;
	if (ma->flags & FS_SYNC_FL)
		ma->fsx_xflags |= FS_XFLAG_SYNC;
	if (ma->flags & FS_IMMUTABLE_FL)
		ma->fsx_xflags |= FS_XFLAG_IMMUTABLE;
	if (ma->flags & FS_APPEND_FL)
		ma->fsx_xflags |= FS_XFLAG_APPEND;
	if (ma->flags & FS_NODUMP_FL)
		ma->fsx_xflags |= FS_XFLAG_NODUMP;
	if (ma->flags & FS_NOATIME_FL)
		ma->fsx_xflags |= FS_XFLAG_NOATIME;
	if (ma->flags & FS_DAX_FL)
		ma->fsx_xflags |= FS_XFLAG_DAX;
	if (ma->flags & FS_PROJINHERIT_FL)
		ma->fsx_xflags |= FS_XFLAG_PROJINHERIT;
}
EXPORT_SYMBOL(miscattr_fill_flags);

/**
 * vfs_miscattr_get - retrieve miscellaneous inode attributes
 * @dentry:	the object to retrieve from
 * @ma:		miscattr pointer
 *
 * Call i_op->miscattr_get() callback, if exists.
 *
 * Returns 0 on success, or a negative error on failure.
 */
int vfs_miscattr_get(struct dentry *dentry, struct miscattr *ma)
{
	struct inode *inode = d_inode(dentry);

	if (d_is_special(dentry))
		return -ENOTTY;

	if (!inode->i_op->miscattr_get)
		return -ENOIOCTLCMD;

	return inode->i_op->miscattr_get(dentry, ma);
}
EXPORT_SYMBOL(vfs_miscattr_get);

/**
 * fsxattr_copy_to_user - copy fsxattr to userspace.
 * @ma:		miscattr pointer
 * @ufa:	fsxattr user pointer
 *
 * Returns 0 on success, or -EFAULT on failure.
 */
int fsxattr_copy_to_user(const struct miscattr *ma, struct fsxattr __user *ufa)
{
	struct fsxattr fa = {
		.fsx_xflags	= ma->fsx_xflags,
		.fsx_extsize	= ma->fsx_extsize,
		.fsx_nextents	= ma->fsx_nextents,
		.fsx_projid	= ma->fsx_projid,
		.fsx_cowextsize	= ma->fsx_cowextsize,
	};

	if (copy_to_user(ufa, &fa, sizeof(fa)))
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL(fsxattr_copy_to_user);

static int fsxattr_copy_from_user(struct miscattr *ma,
				  struct fsxattr __user *ufa)
{
	struct fsxattr fa;

	if (copy_from_user(&fa, ufa, sizeof(fa)))
		return -EFAULT;

	miscattr_fill_xflags(ma, fa.fsx_xflags);
	ma->fsx_extsize = fa.fsx_extsize;
	ma->fsx_nextents = fa.fsx_nextents;
	ma->fsx_projid = fa.fsx_projid;
	ma->fsx_cowextsize = fa.fsx_cowextsize;

	return 0;
}

/*
 * Generic function to check FS_IOC_FSSETXATTR/FS_IOC_SETFLAGS values and reject
 * any invalid configurations.
 *
 * Note: must be called with inode lock held.
 */
static int miscattr_set_prepare(struct inode *inode,
			      const struct miscattr *old_ma,
			      struct miscattr *ma)
{
	int err;

	/*
	 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
	 * the relevant capability.
	 */
	if ((ma->flags ^ old_ma->flags) & (FS_APPEND_FL | FS_IMMUTABLE_FL) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		return -EPERM;

	err = fscrypt_prepare_setflags(inode, old_ma->flags, ma->flags);
	if (err)
		return err;

	/*
	 * Project Quota ID state is only allowed to change from within the init
	 * namespace. Enforce that restriction only if we are trying to change
	 * the quota ID state. Everything else is allowed in user namespaces.
	 */
	if (current_user_ns() != &init_user_ns) {
		if (old_ma->fsx_projid != ma->fsx_projid)
			return -EINVAL;
		if ((old_ma->fsx_xflags ^ ma->fsx_xflags) &
				FS_XFLAG_PROJINHERIT)
			return -EINVAL;
	}

	/* Check extent size hints. */
	if ((ma->fsx_xflags & FS_XFLAG_EXTSIZE) && !S_ISREG(inode->i_mode))
		return -EINVAL;

	if ((ma->fsx_xflags & FS_XFLAG_EXTSZINHERIT) &&
			!S_ISDIR(inode->i_mode))
		return -EINVAL;

	if ((ma->fsx_xflags & FS_XFLAG_COWEXTSIZE) &&
	    !S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return -EINVAL;

	/*
	 * It is only valid to set the DAX flag on regular files and
	 * directories on filesystems.
	 */
	if ((ma->fsx_xflags & FS_XFLAG_DAX) &&
	    !(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)))
		return -EINVAL;

	/* Extent size hints of zero turn off the flags. */
	if (ma->fsx_extsize == 0)
		ma->fsx_xflags &= ~(FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT);
	if (ma->fsx_cowextsize == 0)
		ma->fsx_xflags &= ~FS_XFLAG_COWEXTSIZE;

	return 0;
}

/**
 * vfs_miscattr_set - change miscellaneous inode attributes
 * @dentry:	the object to change
 * @ma:		miscattr pointer
 *
 * After verifying permissions, call i_op->miscattr_set() callback, if
 * exists.
 *
 * Verifying attributes involves retrieving current attributes with
 * i_op->miscattr_get(), this also allows initilaizing attributes that have
 * not been set by the caller to current values.  Inode lock is held
 * thoughout to prevent racing with another instance.
 *
 * Returns 0 on success, or a negative error on failure.
 */
int vfs_miscattr_set(struct user_namespace *mnt_userns, struct dentry *dentry,
		     struct miscattr *ma)
{
	struct inode *inode = d_inode(dentry);
	struct miscattr old_ma = {};
	int err;

	if (d_is_special(dentry))
		return -ENOTTY;

	if (!inode->i_op->miscattr_set)
		return -ENOIOCTLCMD;

	if (!inode_owner_or_capable(mnt_userns, inode))
		return -EPERM;

	inode_lock(inode);
	err = vfs_miscattr_get(dentry, &old_ma);
	if (!err) {
		/* initialize missing bits from old_ma */
		if (ma->flags_valid) {
			ma->fsx_xflags |= old_ma.fsx_xflags & ~FS_XFLAG_COMMON;
			ma->fsx_extsize = old_ma.fsx_extsize;
			ma->fsx_nextents = old_ma.fsx_nextents;
			ma->fsx_projid = old_ma.fsx_projid;
			ma->fsx_cowextsize = old_ma.fsx_cowextsize;
		} else {
			ma->flags |= old_ma.flags & ~FS_COMMON_FL;
		}
		err = miscattr_set_prepare(inode, &old_ma, ma);
		if (!err)
			err = inode->i_op->miscattr_set(mnt_userns, dentry, ma);
	}
	inode_unlock(inode);

	return err;
}
EXPORT_SYMBOL(vfs_miscattr_set);

static int ioctl_getflags(struct file *file, void __user *argp)
{
	struct miscattr ma = { .flags_valid = true }; /* hint only */
	unsigned int flags;
	int err;

	err = vfs_miscattr_get(file_dentry(file), &ma);
	if (!err) {
		flags = ma.flags;
		if (copy_to_user(argp, &flags, sizeof(flags)))
			err = -EFAULT;
	}
	return err;
}

static int ioctl_setflags(struct file *file, void __user *argp)
{
	struct miscattr ma;
	unsigned int flags;
	int err;

	if (copy_from_user(&flags, argp, sizeof(flags)))
		return -EFAULT;

	err = mnt_want_write_file(file);
	if (!err) {
		miscattr_fill_flags(&ma, flags);
		err = vfs_miscattr_set(file_mnt_user_ns(file), file_dentry(file), &ma);
		mnt_drop_write_file(file);
	}
	return err;
}

static int ioctl_fsgetxattr(struct file *file, void __user *argp)
{
	struct miscattr ma = { .xattr_valid = true }; /* hint only */
	int err;

	err = vfs_miscattr_get(file_dentry(file), &ma);
	if (!err)
		err = fsxattr_copy_to_user(&ma, argp);

	return err;
}

static int ioctl_fssetxattr(struct file *file, void __user *argp)
{
	struct miscattr ma;
	int err;

	err = fsxattr_copy_from_user(&ma, argp);
	if (!err) {
		err = mnt_want_write_file(file);
		if (!err) {
			err = vfs_miscattr_set(file_mnt_user_ns(file), file_dentry(file), &ma);
			mnt_drop_write_file(file);
		}
	}
	return err;
}

/*
 * do_vfs_ioctl() is not for drivers and not intended to be EXPORT_SYMBOL()'d.
 * It's just a simple helper for sys_ioctl and compat_sys_ioctl.
 *
 * When you add any new common ioctls to the switches above and below,
 * please ensure they have compatible arguments in compat mode.
 */
static int do_vfs_ioctl(struct file *filp, unsigned int fd,
			unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct inode *inode = file_inode(filp);

	switch (cmd) {
	case FIOCLEX:
		set_close_on_exec(fd, 1);
		return 0;

	case FIONCLEX:
		set_close_on_exec(fd, 0);
		return 0;

	case FIONBIO:
		return ioctl_fionbio(filp, argp);

	case FIOASYNC:
		return ioctl_fioasync(fd, filp, argp);

	case FIOQSIZE:
		if (S_ISDIR(inode->i_mode) || S_ISREG(inode->i_mode) ||
		    S_ISLNK(inode->i_mode)) {
			loff_t res = inode_get_bytes(inode);
			return copy_to_user(argp, &res, sizeof(res)) ?
					    -EFAULT : 0;
		}

		return -ENOTTY;

	case FIFREEZE:
		return ioctl_fsfreeze(filp);

	case FITHAW:
		return ioctl_fsthaw(filp);

	case FS_IOC_FIEMAP:
		return ioctl_fiemap(filp, argp);

	case FIGETBSZ:
		/* anon_bdev filesystems may not have a block size */
		if (!inode->i_sb->s_blocksize)
			return -EINVAL;

		return put_user(inode->i_sb->s_blocksize, (int __user *)argp);

	case FICLONE:
		return ioctl_file_clone(filp, arg, 0, 0, 0);

	case FICLONERANGE:
		return ioctl_file_clone_range(filp, argp);

	case FIDEDUPERANGE:
		return ioctl_file_dedupe_range(filp, argp);

	case FIONREAD:
		if (!S_ISREG(inode->i_mode))
			return vfs_ioctl(filp, cmd, arg);

		return put_user(i_size_read(inode) - filp->f_pos,
				(int __user *)argp);

	case FS_IOC_GETFLAGS:
		return ioctl_getflags(filp, argp);

	case FS_IOC_SETFLAGS:
		return ioctl_setflags(filp, argp);

	case FS_IOC_FSGETXATTR:
		return ioctl_fsgetxattr(filp, argp);

	case FS_IOC_FSSETXATTR:
		return ioctl_fssetxattr(filp, argp);

	default:
		if (S_ISREG(inode->i_mode))
			return file_ioctl(filp, cmd, argp);
		break;
	}

	return -ENOIOCTLCMD;
}

SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{
	struct fd f = fdget(fd);
	int error;

	if (!f.file)
		return -EBADF;

	error = security_file_ioctl(f.file, cmd, arg);
	if (error)
		goto out;

	error = do_vfs_ioctl(f.file, fd, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = vfs_ioctl(f.file, cmd, arg);

out:
	fdput(f);
	return error;
}

#ifdef CONFIG_COMPAT
/**
 * compat_ptr_ioctl - generic implementation of .compat_ioctl file operation
 *
 * This is not normally called as a function, but instead set in struct
 * file_operations as
 *
 *     .compat_ioctl = compat_ptr_ioctl,
 *
 * On most architectures, the compat_ptr_ioctl() just passes all arguments
 * to the corresponding ->ioctl handler. The exception is arch/s390, where
 * compat_ptr() clears the top bit of a 32-bit pointer value, so user space
 * pointers to the second 2GB alias the first 2GB, as is the case for
 * native 32-bit s390 user space.
 *
 * The compat_ptr_ioctl() function must therefore be used only with ioctl
 * functions that either ignore the argument or pass a pointer to a
 * compatible data type.
 *
 * If any ioctl command handled by fops->unlocked_ioctl passes a plain
 * integer instead of a pointer, or any of the passed data types
 * is incompatible between 32-bit and 64-bit architectures, a proper
 * handler is required instead of compat_ptr_ioctl.
 */
long compat_ptr_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (!file->f_op->unlocked_ioctl)
		return -ENOIOCTLCMD;

	return file->f_op->unlocked_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
EXPORT_SYMBOL(compat_ptr_ioctl);

COMPAT_SYSCALL_DEFINE3(ioctl, unsigned int, fd, unsigned int, cmd,
		       compat_ulong_t, arg)
{
	struct fd f = fdget(fd);
	int error;

	if (!f.file)
		return -EBADF;

	/* RED-PEN how should LSM module know it's handling 32bit? */
	error = security_file_ioctl(f.file, cmd, arg);
	if (error)
		goto out;

	switch (cmd) {
	/* FICLONE takes an int argument, so don't use compat_ptr() */
	case FICLONE:
		error = ioctl_file_clone(f.file, arg, 0, 0, 0);
		break;

#if defined(CONFIG_X86_64)
	/* these get messy on amd64 due to alignment differences */
	case FS_IOC_RESVSP_32:
	case FS_IOC_RESVSP64_32:
		error = compat_ioctl_preallocate(f.file, 0, compat_ptr(arg));
		break;
	case FS_IOC_UNRESVSP_32:
	case FS_IOC_UNRESVSP64_32:
		error = compat_ioctl_preallocate(f.file, FALLOC_FL_PUNCH_HOLE,
				compat_ptr(arg));
		break;
	case FS_IOC_ZERO_RANGE_32:
		error = compat_ioctl_preallocate(f.file, FALLOC_FL_ZERO_RANGE,
				compat_ptr(arg));
		break;
#endif

	/*
	 * These access 32-bit values anyway so no further handling is
	 * necessary.
	 */
	case FS_IOC32_GETFLAGS:
	case FS_IOC32_SETFLAGS:
		cmd = (cmd == FS_IOC32_GETFLAGS) ?
			FS_IOC_GETFLAGS : FS_IOC_SETFLAGS;
		fallthrough;
	/*
	 * everything else in do_vfs_ioctl() takes either a compatible
	 * pointer argument or no argument -- call it with a modified
	 * argument.
	 */
	default:
		error = do_vfs_ioctl(f.file, fd, cmd,
				     (unsigned long)compat_ptr(arg));
		if (error != -ENOIOCTLCMD)
			break;

		if (f.file->f_op->compat_ioctl)
			error = f.file->f_op->compat_ioctl(f.file, cmd, arg);
		if (error == -ENOIOCTLCMD)
			error = -ENOTTY;
		break;
	}

 out:
	fdput(f);

	return error;
}
#endif
