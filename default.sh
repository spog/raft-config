#!/bin/bash
#
# The RAFT-CONFIG project build rules
#
# Copyright (C) 2017 Samo Pogacnik <samo_pogacnik@t-2.net>
# All rights reserved.
#
# This file is part of the RAFT-CONFIG software project.
# This file is provided under the terms of the BSD 3-Clause license,
# available in the LICENSE file of the "daemonize" software project.
#
#set -x
set -e

function subdirs_conf()
{
	export TOPDIR=$1
#	echo "SUBPATH: "$TOPDIR

	for SUBDIR in $SUBDIRS;
	do
		export SUBDIR
		mkdir -p $SUBDIR
		make -C $SUBDIR -f $SRCDIR/$TOPDIR/$SUBDIR/$CONFFILE conf
	done
}

function generate_makefile()
{
	if [ "x"$TOPDIR == "x" ]; then
		TOPDIR=.
	fi
	if [ "x"$SUBDIR == "x" ]; then
		SUBDIR=.
	fi
	echo "SUBPATH := "$TOPDIR > $MAKEFILE
	echo "SUBDIR := "$SUBDIR >> $MAKEFILE
	echo "PREFIX := "$prefix_inst_path >> $MAKEFILE
	echo "SRCDIR := "$SRCDIR >> $MAKEFILE
	echo "BUILDIR := "$BUILDIR >> $MAKEFILE
	echo "export SUBPATH SUBDIR PREFIX BUILDIR" >> $MAKEFILE
	cat $SRCDIR/$TOPDIR/$CONFFILE >> $MAKEFILE
#	echo "Done generating ${TOPDIR}/${MAKEFILE}!"
	echo "Done!"
}

function subdirs_make()
{
	for SUBDIR in $SUBDIRS;
	do
		export SUBDIR
		make -C $SUBDIR -f $MAKEFILE $1
	done
}

$1 $2

