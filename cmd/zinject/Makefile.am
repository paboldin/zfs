include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I${top_srcdir}/lib/libspl/include \
	-I${top_srcdir}/lib/libefi/include \
	-I${top_srcdir}/lib/libzpool/include \
	-I${top_srcdir}/lib/libuutil/include \
	-I${top_srcdir}/lib/libzfs/include \
	-I${top_srcdir}/lib/libnvpair/include \
	-I${top_srcdir}/module/zfs \
	-I${top_srcdir}/module/zfs/include \
	-I${top_srcdir}/module/zcommon/include \
	-I${top_srcdir}/module/nvpair/include \
	-I${top_srcdir}/module/avl/include \
	-I${top_srcdir}/module/unicode/include

sbin_PROGRAMS = zinject

zinject_SOURCES = \
	${top_srcdir}/cmd/zinject/translate.c \
	${top_srcdir}/cmd/zinject/zinject.c \
	${top_srcdir}/cmd/zinject/zinject.h

zinject_LDADD = \
	$(top_builddir)/lib/libspl/libspl.la \
	$(top_builddir)/lib/libavl/libavl.la \
	$(top_builddir)/lib/libefi/libefi.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libunicode/libunicode.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la

zinject_LDFLAGS = -pthread -lm $(ZLIB) -lrt $(LIBUUID) $(LIBBLKID)
