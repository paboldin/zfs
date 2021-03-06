include $(top_srcdir)/config/Rules.am

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

SUBDIRS = include
DEFAULT_INCLUDES += \
	-I${top_srcdir}/lib/libzpool/include \
	-I${top_srcdir}/lib/libspl/include \
	-I${top_srcdir}/lib/libnvpair/include \
	-I${top_srcdir}/module/zcommon/include \
	-I${top_srcdir}/module/nvpair/include \
	-I${top_srcdir}/module/avl/include \
	-I${top_srcdir}/module/unicode/include \
	-I${top_srcdir}/module/zfs/include

lib_LTLIBRARIES = libzpool.la

libzpool_la_LIBADD = \
	${top_srcdir}/lib/libunicode/libunicode.la \
	${top_srcdir}/lib/libavl/libavl.la \
	${top_srcdir}/lib/libspl/libspl.la

libzpool_la_SOURCES = \
	${top_srcdir}/lib/libzpool/kernel.c \
	${top_srcdir}/lib/libzpool/taskq.c \
	${top_srcdir}/lib/libzpool/util.c \
	${top_srcdir}/module/zcommon/zfs_comutil.c \
	${top_srcdir}/module/zcommon/zfs_deleg.c \
	${top_srcdir}/module/zcommon/zfs_fletcher.c \
	${top_srcdir}/module/zcommon/zfs_namecheck.c \
	${top_srcdir}/module/zcommon/zfs_prop.c \
	${top_srcdir}/module/zcommon/zpool_prop.c \
	${top_srcdir}/module/zcommon/zprop_common.c \
	${top_srcdir}/module/zcommon/include/sys/fs \
	${top_srcdir}/module/zcommon/include/sys/fs/zfs.h \
	${top_srcdir}/module/zcommon/include/zfs_comutil.h \
	${top_srcdir}/module/zcommon/include/zfs_deleg.h \
	${top_srcdir}/module/zcommon/include/zfs_fletcher.h \
	${top_srcdir}/module/zcommon/include/zfs_namecheck.h \
	${top_srcdir}/module/zcommon/include/zfs_prop.h \
	${top_srcdir}/module/zfs/arc.c \
	${top_srcdir}/module/zfs/bplist.c \
	${top_srcdir}/module/zfs/bpobj.c \
	${top_srcdir}/module/zfs/dbuf.c \
	${top_srcdir}/module/zfs/ddt.c \
	${top_srcdir}/module/zfs/ddt_zap.c \
	${top_srcdir}/module/zfs/dmu.c \
	${top_srcdir}/module/zfs/dmu_object.c \
	${top_srcdir}/module/zfs/dmu_objset.c \
	${top_srcdir}/module/zfs/dmu_send.c \
	${top_srcdir}/module/zfs/dmu_traverse.c \
	${top_srcdir}/module/zfs/dmu_tx.c \
	${top_srcdir}/module/zfs/dmu_zfetch.c \
	${top_srcdir}/module/zfs/dnode.c \
	${top_srcdir}/module/zfs/dnode_sync.c \
	${top_srcdir}/module/zfs/dsl_dataset.c \
	${top_srcdir}/module/zfs/dsl_deadlist.c \
	${top_srcdir}/module/zfs/dsl_deleg.c \
	${top_srcdir}/module/zfs/dsl_dir.c \
	${top_srcdir}/module/zfs/dsl_pool.c \
	${top_srcdir}/module/zfs/dsl_prop.c \
	${top_srcdir}/module/zfs/dsl_scan.c \
	${top_srcdir}/module/zfs/dsl_synctask.c \
	${top_srcdir}/module/zfs/fm.c \
	${top_srcdir}/module/zfs/gzip.c \
	${top_srcdir}/module/zfs/lzjb.c \
	${top_srcdir}/module/zfs/metaslab.c \
	${top_srcdir}/module/zfs/refcount.c \
	${top_srcdir}/module/zfs/rrwlock.c \
	${top_srcdir}/module/zfs/sa.c \
	${top_srcdir}/module/zfs/sha256.c \
	${top_srcdir}/module/zfs/spa.c \
	${top_srcdir}/module/zfs/spa_boot.c \
	${top_srcdir}/module/zfs/spa_config.c \
	${top_srcdir}/module/zfs/spa_errlog.c \
	${top_srcdir}/module/zfs/spa_history.c \
	${top_srcdir}/module/zfs/spa_misc.c \
	${top_srcdir}/module/zfs/space_map.c \
	${top_srcdir}/module/zfs/txg.c \
	${top_srcdir}/module/zfs/uberblock.c \
	${top_srcdir}/module/zfs/unique.c \
	${top_srcdir}/module/zfs/vdev.c \
	${top_srcdir}/module/zfs/vdev_cache.c \
	${top_srcdir}/module/zfs/vdev_file.c \
	${top_srcdir}/module/zfs/vdev_label.c \
	${top_srcdir}/module/zfs/vdev_mirror.c \
	${top_srcdir}/module/zfs/vdev_missing.c \
	${top_srcdir}/module/zfs/vdev_queue.c \
	${top_srcdir}/module/zfs/vdev_raidz.c \
	${top_srcdir}/module/zfs/vdev_root.c \
	${top_srcdir}/module/zfs/zap.c \
	${top_srcdir}/module/zfs/zap_leaf.c \
	${top_srcdir}/module/zfs/zap_micro.c \
	${top_srcdir}/module/zfs/zfs_byteswap.c \
	${top_srcdir}/module/zfs/zfs_debug.c \
	${top_srcdir}/module/zfs/zfs_fm.c \
	${top_srcdir}/module/zfs/zfs_fuid.c \
	${top_srcdir}/module/zfs/zfs_sa.c \
	${top_srcdir}/module/zfs/zfs_znode.c \
	${top_srcdir}/module/zfs/zil.c \
	${top_srcdir}/module/zfs/zio.c \
	${top_srcdir}/module/zfs/zio_checksum.c \
	${top_srcdir}/module/zfs/zio_compress.c \
	${top_srcdir}/module/zfs/zio_inject.c \
	${top_srcdir}/module/zfs/zle.c \
	${top_srcdir}/module/zfs/include/sys/arc.h \
	${top_srcdir}/module/zfs/include/sys/bplist.h \
	${top_srcdir}/module/zfs/include/sys/dbuf.h \
	${top_srcdir}/module/zfs/include/sys/dmu.h \
	${top_srcdir}/module/zfs/include/sys/dmu_impl.h \
	${top_srcdir}/module/zfs/include/sys/dmu_objset.h \
	${top_srcdir}/module/zfs/include/sys/dmu_traverse.h \
	${top_srcdir}/module/zfs/include/sys/dmu_tx.h \
	${top_srcdir}/module/zfs/include/sys/dmu_zfetch.h \
	${top_srcdir}/module/zfs/include/sys/dnode.h \
	${top_srcdir}/module/zfs/include/sys/dsl_dataset.h \
	${top_srcdir}/module/zfs/include/sys/dsl_deleg.h \
	${top_srcdir}/module/zfs/include/sys/dsl_dir.h \
	${top_srcdir}/module/zfs/include/sys/dsl_pool.h \
	${top_srcdir}/module/zfs/include/sys/dsl_prop.h \
	${top_srcdir}/module/zfs/include/sys/dsl_synctask.h \
	${top_srcdir}/module/zfs/include/sys/metaslab.h \
	${top_srcdir}/module/zfs/include/sys/metaslab_impl.h \
	${top_srcdir}/module/zfs/include/sys/refcount.h \
	${top_srcdir}/module/zfs/include/sys/rrwlock.h \
	${top_srcdir}/module/zfs/include/sys/spa_boot.h \
	${top_srcdir}/module/zfs/include/sys/space_map.h \
	${top_srcdir}/module/zfs/include/sys/spa.h \
	${top_srcdir}/module/zfs/include/sys/spa_impl.h \
	${top_srcdir}/module/zfs/include/sys/txg.h \
	${top_srcdir}/module/zfs/include/sys/txg_impl.h \
	${top_srcdir}/module/zfs/include/sys/uberblock.h \
	${top_srcdir}/module/zfs/include/sys/uberblock_impl.h \
	${top_srcdir}/module/zfs/include/sys/unique.h \
	${top_srcdir}/module/zfs/include/sys/vdev_file.h \
	${top_srcdir}/module/zfs/include/sys/vdev.h \
	${top_srcdir}/module/zfs/include/sys/vdev_impl.h \
	${top_srcdir}/module/zfs/include/sys/zap.h \
	${top_srcdir}/module/zfs/include/sys/zap_impl.h \
	${top_srcdir}/module/zfs/include/sys/zap_leaf.h \
	${top_srcdir}/module/zfs/include/sys/zfs_acl.h \
	${top_srcdir}/module/zfs/include/sys/zfs_context.h \
	${top_srcdir}/module/zfs/include/sys/zfs_ctldir.h \
	${top_srcdir}/module/zfs/include/sys/zfs_debug.h \
	${top_srcdir}/module/zfs/include/sys/zfs_dir.h \
	${top_srcdir}/module/zfs/include/sys/zfs_fuid.h \
	${top_srcdir}/module/zfs/include/sys/zfs_ioctl.h \
	${top_srcdir}/module/zfs/include/sys/zfs_rlock.h \
	${top_srcdir}/module/zfs/include/sys/zfs_vfsops.h \
	${top_srcdir}/module/zfs/include/sys/zfs_znode.h \
	${top_srcdir}/module/zfs/include/sys/zil.h \
	${top_srcdir}/module/zfs/include/sys/zil_impl.h \
	${top_srcdir}/module/zfs/include/sys/zio_checksum.h \
	${top_srcdir}/module/zfs/include/sys/zio_compress.h \
	${top_srcdir}/module/zfs/include/sys/zio.h \
	${top_srcdir}/module/zfs/include/sys/zio_impl.h \
	${top_srcdir}/module/zfs/include/sys/zvol.h \
	${top_srcdir}/module/zfs/include/sys/fm/protocol.h \
	${top_srcdir}/module/zfs/include/sys/fm/util.h \
	${top_srcdir}/module/zfs/include/sys/fm/fs/zfs.h

libzpool_la_LDFLAGS = -pthread
