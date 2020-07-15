#
# Copyright (c) 2012 Citrix Systems, Inc.
# Copyright (c) 2015 Assured Information Security, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

#
#
# Makefile.am:
#
#

CPROTO=cproto
INCLUDES =  ${LIBXC_INC} ${LIBXCDBUS_INC} ${LIBXENACPI_INC} ${DBUS_GLIB_1_INC} ${GLIB_20_INC} ${LIBXCXENSTORE_CFLAGS}

DBUS_CLIENT_IDLS=xenmgr xenmgr_vm db
DBUS_SERVER_IDLS=xcpmd

noinst_HEADERS=project.h prototypes.h xcpmd.h rules.h modules.h default-inputs-module.h list.h battery.h parser.h db-helper.h vm-utils.h

sbin_PROGRAMS = xcpmd

BUILT_SOURCES = ${DBUS_CLIENT_IDLS:%=rpcgen/%_client.h} \
	${DBUS_SERVER_IDLS:%=rpcgen/%_server_marshall.h} \
	${DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.c} \
	${DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.h} \
	version.h


# Use libtool to build our .so files.
pkglib_LTLIBRARIES = default-actions-module.la acpi-module.la vm-actions-module.la default-inputs-module.la vm-events-module.la idle-detect-module.la displayhandler-module.la

default_inputs_module_la_SOURCES = default-inputs-module.c default-inputs-module.h rules.h
default_inputs_module_la_LDFLAGS = -avoid-version -module -shared

default_actions_module_la_SOURCES = default-actions-module.c rules.h
default_actions_module_la_LDFLAGS = -avoid-version -module -shared

acpi_module_la_SOURCES = acpi-module.c project.h xcpmd.h rules.h acpi-module.h battery.h
acpi_module_la_LDFLAGS = -avoid-version -module -shared

vm_actions_module_la_SOURCES = vm-actions-module.c project.h xcpmd.h rules.h rpcgen/xenmgr_client.h rpcgen/xenmgr_vm_client.h vm-utils.h
vm_actions_module_la_LDFLAGS = -avoid-version -module -shared

vm_events_module_la_SOURCES = vm-events-module.c project.h xcpmd.h modules.h rules.h vm-events-module.h vm-utils.h
vm_events_module_la_LDFLAGS = -avoid-version -module -shared



displayhandler_module_la_SOURCES = displayhandler-module.c rules.h
displayhandler_module_la_LDFLAGS = -avoid-version -module -shared

idle_detect_module_la_SOURCES = idle-detect-module.c project.h xcpmd.h rules.h idle-detect-module.h rpcgen/input_daemon_client.h vm-utils.h
idle_detect_module_la_LDFLAGS = -avoid-version -module -shared

SRCS=xcpmd.c acpi-events.c platform.c rpcgen/xcpmd_server_obj.c xcpmd-dbus-server.c utils.c rules.c modules.c battery.c parser.c db-helper.c vm-utils.c
xcpmd_SOURCES = ${SRCS}
xcpmd_LDADD = -lm -ldl -lpci -levent -lyajl ${LIBXC_LIB} ${LIBXCDBUS_LIB} ${LIBXENACPI_LIB} ${DBUS_GLIB_1_LIB} ${GLIB_20_LIB} ${LIBXCXENSTORE_LIBS} ${LIBNL_LIBS} ${LIBNL_GENL_LIBS}
xcpmd_LDFLAGS = -rdynamic


AM_CFLAGS=-g -W -Wall -Werror -std=gnu99

# Discard the .la files libtool produces.
install-exec-hook:
	rm $(DESTDIR)$(libdir)/$(PACKAGE)/*.la


VFD=${srcdir}/..
VF=${shell cat ${VFD}/version-files}
VFS=${VF:%=${VFD}/%}
VCHK=${shell cat ${VFS} | @MD5SUM@ | @AWK@ '{print $$1 }' }
VNUM=${shell @GREP@ ${VCHK} ${VFD}/version-md5sums | @AWK@ '{ print $$2 }'  }
VDEF=${shell echo `cat ${VFD}/version-major`.`cat ${VFD}/version-minor`.`cat ${VFD}/version-micro` }

rpcgen/%_client.h: ${IDLDIR}/%.xml
	mkdir -p rpcgen
	${XC_RPCGEN} --templates-dir=${RPCGEN_TEMPLATES} -c -o rpcgen/ $<


rpcgen/%_server_marshall.h rpcgen/%_server_obj.h rpcgen/%_server_obj.c : ${IDLDIR}/%.xml
	mkdir -p rpcgen
	${XC_RPCGEN} --templates-dir=${RPCGEN_TEMPLATES} -s -o rpcgen/ $<

protos:
	echo > prototypes.h
	${CPROTO} -v `echo ${INCLUDES} | sed -e 's/-pthread//g'` ${SRCS} > prototypes.tmp
	mv -f prototypes.tmp prototypes.h


version.h: $(VFD)/version-files $(VFD)/version-major \
	$(VFD)/version-minor $(VFD)/version-micro \
	$(VFD)/version-md5sums ${VFS} Makefile
	if [ .${VNUM} = . ]; then \
		echo "#define VERSION \"xcpmd Version ${VDEF} + Edits\"" > version.h; \
		echo ${VDEF}-E > version-num; \
	else \
		echo "#define VERSION \"xcpmd Version ${VNUM}\"" > version.h; \
		echo ${VNUM} > version-num; \
	fi

