#! /usr/bin/ksh
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2013 Joyent, Inc. All rights reserved.
#

#
# Use print() on userland CTF types and verify we get the data we
# expect. This time, use $target to make sure that path works correctly.
#

if [ $# != 1 ]; then
        echo expected one argument: '<'dtrace-path'>'
        exit 2
fi

dtrace=$1
t="final_fantasy_info_t"
exe="tst.printtype.exe"

elfdump -c "./$exe" | grep -Fq 'sh_name: .SUNW_ctf' 
if [[ $? -ne 0 ]]; then
	echo "CTF does not exist in $exe, that's a bug" >&2
	exit 1
fi

./$exe &
pid=$!

$dtrace -Ep $pid -qs /dev/stdin <<EOF
pid\$target::ff_getgameid:entry
/next == 0/
{
	print(*args[0]);
	printf("\n");
	next = 1;
}

pid\$target::ff_getpartysize:entry
/next == 1/
{
	print(*args[0]);
	printf("\n");
	next = 2;
}

pid\$target::ff_getsummons:entry
/next == 2/
{
	print(*args[0]);
	printf("\n");
	exit(0);
}
EOF
rc=$?

kill -9 $pid

exit $rc
