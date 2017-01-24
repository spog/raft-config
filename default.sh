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

function subdirs_conf()
{
	for SUBDIR in $SUBDIRS;
	do
		export SUBDIR
		echo "SUBDIR: "$SUBDIR
		mkdir -p $SUBDIR
		make -C $SUBDIR -f $comp_source_DIR/$SUBDIR/$CONFFILE conf
	done
}

function generate_makefile()
{
	if [ "x"$SUBDIR == "x" ]; then
		SUBDIR=.
	fi
	echo "SUBDIR := "$SUBDIR > $MAKEFILE
	echo "export SUBDIR" >> $MAKEFILE
	cat $comp_source_DIR/$SUBDIR/$CONFFILE >> $MAKEFILE
}

function subdirs_make()
{
	for SUBDIR in $SUBDIRS;
	do
		export SUBDIR
		echo "SUBDIR: "$SUBDIR
		mkdir -p $SUBDIR
		make -C $SUBDIR -f $MAKEFILE $1
	done
}

$1 $2

