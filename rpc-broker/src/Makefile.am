AM_CFLAGS = -g -Wall -lpthread \
 $(DBUS_CFLAGS) $(LIBWEBSOCKETS_CFLAGS) \
 $(JSON_C_CFLAGS) $(LIBXML_CFLAGS)

sbin_PROGRAMS = rpc-broker

rpc_broker_SOURCES = \
    rpc-broker.c \
    websockets.c \
    policy.c \
    rpc-dbus.c \
    msg.c \
    rpc-json.c \
    signature.c \
    rpc-broker.h

noinst_HEADERS = rpc-broker.h

rpc_broker_LDADD = \
    $(DBUS_LIBS) \
    $(LIBWEBSOCKETS_LIBS) \
    $(JSON_C_LIBS) \
    $(LIBXML_LIBS) \
    $(XENSTORE_LIBS) \
    -luv
