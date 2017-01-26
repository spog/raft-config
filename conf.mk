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

include $(SRCDIR)/default.mk
TOPDIR := .

SUBDIRS := src
export SUBDIRS

.PHONY: all
all:
	$(SRCDIR)/default.sh subdirs_make all

.PHONY: install
install:
	$(SRCDIR)/default.sh subdirs_make install

