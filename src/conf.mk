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

include $(_SRCDIR_)/default.mk

TARGET := raft-config
TPATH := $(_BUILD_PREFIX_)/sbin
IPATH := $(_INSTALL_PREFIX_)/sbin

.PHONY: all
all: $(TPATH)/$(TARGET) subdirs_all

$(TPATH)/$(TARGET): $(_SRCDIR_)/$(SUBPATH)/raft-config.c $(_SRCDIR_)/$(SUBPATH)/raft-config.h $(TPATH)
	$(CC) -o $@ $(shell pkg-config --cflags --libs libnl-genl-3.0) $<

$(TPATH):
	install -d $@

.PHONY: install
install: $(IPATH) $(IPATH)/$(TARGET)

$(IPATH):
	install -d $@

$(IPATH)/$(TARGET):
	install -s $(TPATH)/$(TARGET) $@

##
# Subdirs to handle:
##
SUBDIRS := utils tools
export SUBDIRS

.PHONY: subdirs_all
subdirs_all:
	$(_SRCDIR_)/default.sh subdirs_make all

.PHONY: subdirs_install
subdirs_install:
	$(_SRCDIR_)/default.sh subdirs_make install

