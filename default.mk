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

SHELL := /bin/bash
MAKEFILE := Makefile
CONFFILE := conf.mk
BUILD_PREFIX := $(BUILDIR)/./$(PREFIX)
INSTALL_PREFIX := $(DESTDIR)/$(PREFIX)
export SHELL MAKEFILE CONFFILE BUILD_PREFIX INSTALL_PREFIX

TOPDIR := $(TOPDIR)/$(SUBDIR)

.PHONY: conf

conf: $(MAKEFILE)
	@$(comp_source_DIR)/default.sh subdirs_conf $(TOPDIR)

$(MAKEFILE):
	@echo "Generating $(TOPDIR)/$@"
	@$(comp_source_DIR)/default.sh generate_makefile $(SUBDIR)

