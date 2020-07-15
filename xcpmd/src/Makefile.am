AM_CFLAGS = \
	-g -W -Wall -Werror -std=gnu99 \
	$(LIBPCI_CFLAGS) \
	$(LIBNL_CFLAGS) \
	$(LIBNL_GENL_CFLAGS) \
	$(LIBEVENT_CFLAGS) \
	$(DBUS_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(DBUS_GLIB_CFLAGS) \
	$(LIBXCDBUS_CFLAGS) \
	$(LIBXCXENSTORE_CFLAGS)

#
# xcpmd daemon.
#
noinst_HEADERS = \
	project.h \
	prototypes.h \
	xcpmd.h \
	rules.h \
	modules.h \
	default-inputs-module.h \
	list.h \
	battery.h \
	parser.h \
	db-helper.h \
	vm-utils.h

sbin_PROGRAMS = xcpmd

xcpmd_SOURCES = \
	acpi-events.c \
	battery.c \
	db-helper.c \
	modules.c \
	parser.c \
	platform.c \
	rpcgen/xcpmd_server_obj.c \
	rules.c \
	utils.c \
	vm-utils.c \
	xcpmd-dbus-server.c \
	xcpmd.c

xcpmd_LDADD = \
	$(LIBPCI_LIBS) \
	$(LIBNL_LIBS) \
	$(LIBNL_GENL_LIBS) \
	$(LIBEVENT_LIBS) \
	$(DBUS_LIBS) \
	$(GLIB_LIBS) \
	$(DBUS_GLIB_LIBS) \
	$(LIBXCDBUS_LIBS) \
	$(LIBXCXENSTORE_LIBS)
xcpmd_LDFLAGS = -rdynamic

#
# RPC generated stubs.
#
DBUS_CLIENT_IDLS = xenmgr xenmgr_vm db
DBUS_SERVER_IDLS = xcpmd

BUILT_SOURCES = \
	$(DBUS_CLIENT_IDLS:%=rpcgen/%_client.h) \
	$(DBUS_SERVER_IDLS:%=rpcgen/%_server_marshall.h) \
	$(DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.c) \
	$(DBUS_SERVER_IDLS:%=rpcgen/%_server_obj.h)

rpcgen/%_client.h: $(IDLDIR)/%.xml
	mkdir -p rpcgen
	$(XC_RPCGEN) --templates-dir=$(RPCGEN_TEMPLATES) -c -o rpcgen/ $<

rpcgen/%_server_marshall.h rpcgen/%_server_obj.h rpcgen/%_server_obj.c: $(IDLDIR)/%.xml
	mkdir -p rpcgen
	$(XC_RPCGEN) --templates-dir=$(RPCGEN_TEMPLATES) -s -o rpcgen/ $<

#
# Modules.
#
pkglib_LTLIBRARIES = \
	acpi-module.la \
	default-actions-module.la \
	default-inputs-module.la \
	displayhandler-module.la \
	idle-detect-module.la \
	vm-actions-module.la \
	vm-events-module.la

acpi_module_la_SOURCES = \
	acpi-module.c \
	acpi-module.h \
	battery.h \
	project.h \
	rules.h \
	xcpmd.h
acpi_module_la_LDFLAGS = -avoid-version -module -shared

default_inputs_module_la_SOURCES = \
	default-inputs-module.c \
	default-inputs-module.h \
	rules.h
default_inputs_module_la_LDFLAGS = -avoid-version -module -shared

default_actions_module_la_SOURCES = \
	default-actions-module.c \
	rules.h
default_actions_module_la_LDFLAGS = -avoid-version -module -shared

displayhandler_module_la_SOURCES = \
	displayhandler-module.c \
	rules.h
displayhandler_module_la_LDFLAGS = -avoid-version -module -shared

idle_detect_module_la_SOURCES = \
	idle-detect-module.c \
	idle-detect-module.h \
	project.h \
	rpcgen/input_daemon_client.h \
	rules.h \
	vm-utils.h \
	xcpmd.h
idle_detect_module_la_LDFLAGS = -avoid-version -module -shared

vm_actions_module_la_SOURCES = \
	vm-actions-module.c \
	project.h \
	xcpmd.h \
	rules.h \
	rpcgen/xenmgr_client.h \
	rpcgen/xenmgr_vm_client.h \
	vm-utils.h
vm_actions_module_la_LDFLAGS = -avoid-version -module -shared

vm_events_module_la_SOURCES = \
	modules.h \
	project.h \
	rules.h \
	vm-events-module.c \
	vm-events-module.h \
	vm-utils.h \
	xcpmd.h
vm_events_module_la_LDFLAGS = -avoid-version -module -shared
