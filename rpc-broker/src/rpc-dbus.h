/*
 * Copyright (c) 2019 Assured Information Security, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file rpc-dbus.h
 * @author Tim Konick <konickt@ainfosec.com>
 * @date March 4, 2019
 * @brief DBus function handling declarations.
 *
 * All globals state variables for handling dbus communications and data
 * structures dbus functions need.
 */

#define DBUS_BROKER_CLIENT_TIMEOUT  100
#define DBUS_BROKER_MSG_TIMEOUT     100

/* DBus-Broker messages */
#define DBUS_REQ_TIMEOUT    5000
#define DBUS_MSG_LEN        8192
#define DBUS_ARG_LEN        1024

#define DBUS_INTROSPECT_MAX 0xFFFF

#define DBUS_MAX_ARG_LEN    16

/**
 * @brief A structure containing the tokenized fields of a dbus reqest.
 */
struct dbus_message {
    const char *destination;
    const char *interface;
    const char *path;
    const char *member;
    const char *type;
    uint8_t arg_number;
    char arg_sig[DBUS_MAX_ARG_LEN];
    char json_sig[DBUS_MAX_ARG_LEN];
    void *args[DBUS_MAX_ARG_LEN];
};

#define DBUS_READ "read"
#define DBUS_LIST "list"

#define CLIENT_REQ_LEN       16
#define CLIENT_DBUS_REQ_LEN 256

#define VM_UUID_LEN   33
#define DOMID_UUID_LEN 8
#define DOMID_SECTION 24

#define XENSTORE_TARGET_LEN 8
#define XENSTORE_TARGET "/target"

#define XENMGR_SIGNAL_SERVICE "type='signal',interface='com.citrix.xenclient.xenmgr',member='vm_state_changed'"


/**
 * @brief a dbus signal object kept in a doubly linked-list fashion.
 */
struct dbus_link {
    /* add identifier */
    int signal_type;
    int client_fd;
    int server_fd;
    struct dbus_link *next;
    struct dbus_link *prev;
    struct lws *wsi;
    char *name;
    DBusConnection *dconn;
};

struct dbus_link *dlinks;
size_t signal_subscribers;

/* forward declarations */
struct dbus_broker_server;
struct json_request;

#define DBUS_SIGNAL_TYPE_SERVER 0x1
#define DBUS_SIGNAL_TYPE_CLIENT 0x2


/* src/rpc-dbus.c */
DBusConnection *create_dbus_connection(void);

int start_server(struct dbus_broker_server *server, int port);

void dbus_default(struct dbus_message *dmsg, char *member, void *arg);

int connect_to_system_bus(void);

void *dbus_signal(void *subscriber);

signed int convert_raw_dbus(struct dbus_message *dmsg,
                            const char *msg, size_t len);

DBusMessage *make_dbus_call(DBusConnection *conn, struct dbus_message *dmsg);

char *db_query(DBusConnection *conn, char *arg);

DBusMessage *db_list(void);

char *dbus_introspect(struct json_request *jreq);

void add_ws_signal(DBusConnection *conn, char *signal, struct lws *wsi);

void remove_dlink(struct dbus_link *link);

void free_dlinks(void);

char *get_uuid_from_domid(int domid);

struct dbus_link *add_dbus_signal(void);


#define DBUS_DB_DEST     "com.citrix.xenclient.db"
#define DBUS_DB_IFACE    DBUS_DB_DEST

#define DBUS_VM_PATH     "/vm"
#define DBUS_BASE_PATH   "/"
#define DBUS_BUS_ADDR    "/var/run/dbus/system_bus_socket"
#define DBUS_INTRO_IFACE "org.freedesktop.DBus.Introspectable"
#define DBUS_INTRO_METH  "Introspect"

#define DBUS_COMM_MIN     28

