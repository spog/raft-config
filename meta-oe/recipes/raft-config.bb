DESCRIPTION = "Configuration tools for the kernel RAFT module"
SECTION = "examples"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://${HOME}/RAFT/raft-config/LICENSE;md5=c1a04662a319aaa97873a7fe4dcf1aaf"
PV = "1.0.0"

DEPENDS = "libnl"

#require raft-config-git.inc
#require raft-config-local.inc

#inherit pkgconfig cmake
inherit pkgconfig

SRC_LOCAL_PATH = "${HOME}/RAFT/raft-config"

SRC_URI += " \
   file://${SRC_LOCAL_PATH}/* \
"

do_configure () {
       echo SRC_LOCAL_PATH:
       echo ${SRC_LOCAL_PATH}
       echo S:
       echo ${S}
       echo D:
       echo ${D}
       echo PWD:
       pwd
#       env
#       cmake -DCMAKE_INSTALL_PREFIX=/usr ${S}
#       ${HOME}/U2UP/build.u2up/u2up-build.sh -b ./ -p /usr/local ${S} --conf
#       ../${SRC_LOCAL_PATH}/u2up/u2up-build.sh -b . -p /usr/local ../${SRC_LOCAL_PATH} --conf
       # BUILDIR=${S} # equals to ./
       env PREFIX=/usr/local ../${SRC_LOCAL_PATH}/configure
}

do_compile() {
#       echo S:
#       echo ${S}
#       echo D:
#       echo ${D}
#       echo PWD:
#       pwd
#       env
       oe_runmake
#        ${S}/u2up/u2up-build.sh -b . ${S} --make
}

do_install() {
#       echo S:
#       echo ${S}
#       echo D:
#       echo ${D}
#       echo PWD:
#       pwd
#       env
       oe_runmake install DESTDIR=${D}
#        ${SRC_LOCAL_PATH}/raft-config/u2up/u2up-build.sh -b . -d ${D} ${S} --inst
}

PACKAGES = "${PN}-dbg ${PN}"

FILES_${PN} = "\
/usr/local/sbin/raft-config \
/usr/local/etc/bash_completion.d/raft-config \
"

INSANE_SKIP_${PN} = "ldflags"

