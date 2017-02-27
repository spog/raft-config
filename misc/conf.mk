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

SUBDIRS :=
export SUBDIRS

TARGET := raft-config
TPATH := $(_BUILD_PREFIX_)/etc/bash_completion.d
IPATH := $(_INSTALL_PREFIX_)/etc/bash_completion.d

.PHONY: all
all: $(TPATH)/$(TARGET)

$(TPATH)/$(TARGET): $(_SRCDIR_)/$(SUBPATH)/$(TARGET) $(TPATH)
	cp -pf $< $@

$(TPATH):
	install -d $@

.PHONY: install
install: $(IPATH) $(IPATH)/$(TARGET)

$(IPATH):
	install -d $@

$(IPATH)/$(TARGET):
	install $(TPATH)/$(TARGET) $@

