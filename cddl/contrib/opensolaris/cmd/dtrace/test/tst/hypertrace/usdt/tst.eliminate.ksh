#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

#
# Make sure temporary symbols generated due to DTrace probes in static
# functions are removed in the final link step.
#

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
DIR=/var/tmp/dtest.$$

mkdir $DIR
cd $DIR

cat > prov.d <<EOF
provider test_prov {
	probe go();
};
EOF

$dtrace -Eh -s prov.d
if [ $? -ne 0 ]; then
	print -u2 "failed to generate header file"
	exit 1
fi

cat > test.c <<EOF
#include <sys/types.h>
#include "prov.h"

static void
foo(void)
{
	TEST_PROV_GO();
}

int
main(int argc, char **argv)
{
	foo();

	return (0);
}
EOF

cc -c test.c
if [ $? -ne 0 ]; then
	print -u2 "failed to compile test.c"
	exit 1
fi
$dtrace -EG -s prov.d test.o
if [ $? -ne 0 ]; then
	print -u2 "failed to create DOF"
	exit 1
fi
cc -o test test.o prov.o
if [ $? -ne 0 ]; then
	print -u2 "failed to link final executable"
	exit 1
fi

nm test.o | grep \$dtrace > /dev/null
if [ $? -ne 0 ]; then
	print -u2 "no temporary symbols in the object file"
	exit 1
fi

nm test | grep \$dtrace > /dev/null
if [ $? -eq 0 ]; then
	print -u2 "failed to eliminate temporary symbols"
	exit 1
fi

cd /
/bin/rm -rf $DIR

exit 0
