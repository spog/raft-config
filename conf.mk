#
# The RAFT-CONFIG project build rules
#
# Copyright (C) 2017 Samo Pogacnik <samo_pogacnik@t-2.net>
# All rights reserved.
#
# This file is part of the RAFT-CONFIG software project.
# This file is provided under the terms of the BSD 3-Clause license,
# available in the LICENSE file of the "raft-config" software project.
#

include $(_SRCDIR_)/default.mk
TOPDIR := .

SUBDIRS := src misc
export SUBDIRS

.PHONY: all
all:
	$(_SRCDIR_)/default.sh subdirs_make all

.PHONY: install
install:
	$(_SRCDIR_)/default.sh subdirs_make install

