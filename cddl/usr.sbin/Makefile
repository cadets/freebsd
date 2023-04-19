# $FreeBSD$

.include <src.opts.mk>

SUBDIR.${MK_DTRACE}+= \
	${_dtraced} \
	${_dtracedctl} \
	${_dtrace} \
	${_dwatch} \
	${_lockstat} \
	${_plockstat}

SUBDIR.${MK_TESTS}+= tests

SUBDIR.${MK_ZFS}+= \
	zdb \
	zhack \
	zfsd

.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386"
_dtrace=	dtrace
_dwatch=	dwatch
_lockstat=	lockstat
_plockstat=	plockstat
_dtraced=	dtraced
_dtracedctl=	dtracedctl
.endif

.if ${MACHINE_CPUARCH} == "aarch64" || ${MACHINE_CPUARCH} == "arm" || \
    ${MACHINE_CPUARCH} == "riscv"
_dtrace=	dtrace
_dwatch=	dwatch
_lockstat=	lockstat
.endif

.if ${MACHINE_CPUARCH} == "powerpc"
_dtrace=	dtrace
_dwatch=	dwatch
_lockstat=	lockstat
.endif

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
