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

include $(comp_source_DIR)/default.mk

SUBDIRS := utils tools
export SUBDIRS

.PHONY: all
all: raft-config

raft-config: $(comp_source_DIR)/$(SUBDIR)/raft-config.c $(comp_source_DIR)/$(SUBDIR)/raft-config.h
	$(CC) -o $@ $(shell pkg-config --cflags --libs libnl-genl-3.0) $<

