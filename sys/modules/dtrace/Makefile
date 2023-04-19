# $FreeBSD$

.include "Makefile.inc"
.include <src.opts.mk>

SUBDIR=		dtaudit		\
		dtmalloc	\
		dtnfscl		\
		dtrace		\
		dtraceall	\
		dtrace_test	\
		hypertrace	\
		fbt		\
		profile		\
		prototype	\
		sdt		\
		systrace

.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
SUBDIR+=	fasttrap systrace_linux
.endif
.if ${MACHINE_CPUARCH} == "amd64"
SUBDIR+=	systrace_linux32
SUBDIR+=	kinst
.endif
.if ${MACHINE_CPUARCH} == "powerpc"
SUBDIR+=	fasttrap
.endif
.if ${MACHINE_CPUARCH} == "powerpc"
SUBDIR+=	fbt fasttrap
.endif
.if ${MACHINE_CPUARCH} == "amd64" || \
    ${MACHINE_CPUARCH} == "aarch64" || \
    ${MACHINE_ARCH} == "powerpc64"
SUBDIR+=	systrace_freebsd32
.endif

.include <bsd.subdir.mk>
