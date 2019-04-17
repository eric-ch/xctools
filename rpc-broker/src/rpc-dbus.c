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
 * @file rpc-dbus.c
 * @author Tim Konick <konickt@ainfosec.com>
 * @date March 4, 2019
 * @brief DBus functions.
 *
 * Any dbus connections being made are created through these functions.  Along
 * with any corresponding message handling that is needed aswell.
 */

#include "rpc-broker.h"


/**
 * Makes a dbus connection directly on the bus.
 *
 */
DBusConnection *create_dbus_connection(void)
{
    DBusError error;
    dbus_error_init(&error);
    DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

    if (dbus_error_is_set(&error))
        DBUS_BROKER_WARNING("<DBus Connection Error> [%s]", error.message);

    return conn;
}

/**
 * Initializes a dbus server connection on a given port. 
 *
 * @param server the server object being initialized.
 * @param port the port being bound to.
 *
 * @return 0 on success error code otherwise. 
 */
int start_server(struct dbus_broker_server *server, int port)
{
    int ret;
    int optval;

    memset(&server->peer, 0, sizeof(server->peer));

    ret = socket(AF_INET, SOCK_STREAM, 0);
    if (ret < 0) {
        DBUS_BROKER_WARNING("socket: %s", strerror(errno));
        goto done;
    }

    server->dbus_socket = ret; 
    optval = 1;
    setsockopt(server->dbus_socket, SOL_SOCKET, SO_REUSEPORT,
              &optval, sizeof(optval));

    server->addr.sin_family = AF_INET;
    server->addr.sin_addr.s_addr = INADDR_ANY;
    server->addr.sin_port = htons(port);

    server->peer.sin_family = AF_INET;
    server->peer.sin_addr.s_addr = INADDR_ANY;
    server->peer.sin_port = 0;

    ret = bind(server->dbus_socket, &server->addr, sizeof(server->addr));
    if (ret < 0) {
        DBUS_BROKER_WARNING("bind: %s", strerror(errno));
        goto done;
    }

    ret = listen(server->dbus_socket, 1);
    if (ret < 0) 
        DBUS_BROKER_WARNING("listen: %s", strerror(errno));

done:

    return ret;
}

/**
 * Sets up default fields for a generic dbus reqeuset.
 *
 * @param dmsg the dbus message object being set.
 */
void dbus_default(struct dbus_message *dmsg, char *member, void *arg)
{
    dmsg->destination = DBUS_DB_DEST;
    dmsg->interface = DBUS_DB_IFACE;
    dmsg->path = DBUS_BASE_PATH;
    dmsg->member = member;
    dmsg->args[0] = arg;
    dmsg->arg_number = 1;
    memcpy(dmsg->arg_sig, "s", 2);
}

/**
 * Makes a connection directly to the main running dbus server.
 */
int connect_to_system_bus(void)
{
    int srv;
    struct sockaddr_un addr;

    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0)
        DBUS_BROKER_ERROR("socket");

    addr.sun_family = AF_UNIX;
    /* could have bus-path override (LEN would need checking) */
    memcpy(addr.sun_path, DBUS_BUS_ADDR, strlen(DBUS_BUS_ADDR) + 1);

    if (connect(srv, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        DBUS_BROKER_ERROR("connect");

    return srv;
}

/**
 * Debugging function for requests made over a raw dbus connection.
 *
 * @param dmsg the dbus message request being made.
 * @dbus_msg the dbus api message object.
 */
void debug_raw_msg(struct dbus_message *dmsg, DBusMessage *dbus_msg)
{
    int type;
    DBusMessageIter iter;

    DBUS_BROKER_EVENT("Raw-DBus %s %s %s %s", dmsg->destination, dmsg->path,
                                              dmsg->interface, dmsg->member);

    dbus_message_iter_init(dbus_msg, &iter);

    while ((type = dbus_message_iter_get_arg_type(&iter)) != DBUS_TYPE_INVALID) {

        void *arg;

        switch (type) {

            case DBUS_TYPE_INT32:
            case DBUS_TYPE_UINT32: {
                dbus_message_iter_get_basic(&iter, arg);
                DBUS_BROKER_EVENT("%d", *(int *) arg);
                break;
            }

            case DBUS_TYPE_BOOLEAN: {
                dbus_message_iter_get_basic(&iter, arg);
                DBUS_BROKER_EVENT("bool %d", *(bool *) arg);
                break;
            }

            case DBUS_TYPE_STRING: {
                dbus_message_iter_get_basic(&iter, &arg);
                DBUS_BROKER_EVENT("%s", (char *) arg);
                break;
            }

            case DBUS_TYPE_VARIANT: {
                DBUS_BROKER_EVENT("variant %s", "");
                break;
            }

            default: {
                DBUS_BROKER_EVENT("other %d",  type);
                break;
            }
        }

        dbus_message_iter_next(&iter);
    }
}

/**
 * Used by client communications over port-5555 where, the raw-bytes are being
 * read directly from the client file-descriptor.  The `char` buffer is
 * de-marshalled into a dbus-protocol object `DBusMessage`
 *
 * @param dmsg the dbus message object.
 * @param msg the raw bytes of the request.
 * @param len the number of bytes contained in msg
 *
 * @return 0 on success, error code otherwise
 */
signed int convert_raw_dbus(struct dbus_message *dmsg,
                            const char *msg, size_t len)
{
    DBusError error;
    DBusMessageIter iter;
    DBusMessage *dbus_msg;

    int ret, type, argnum;
    const char *destination, *path, *interface, *member;

    dbus_error_init(&error);
    dbus_msg = NULL;
    dbus_msg = dbus_message_demarshal(msg, len, &error);

    if (dbus_error_is_set(&error)) {
        DBUS_BROKER_WARNING("<De-Marshal failed> [Length: %zu] error: %s",
                              len, error.message);
        return -1;
    }

    destination = dbus_message_get_destination(dbus_msg);
    dmsg->destination = destination ? destination : "NULL";

    path = dbus_message_get_path(dbus_msg);
    dmsg->path = path ? path : "/";

    interface = dbus_message_get_interface(dbus_msg);
    dmsg->interface = interface ? interface : "NULL";

    member = dbus_message_get_member(dbus_msg);
    dmsg->member = member ? member : "NULL";

    ret = dbus_message_get_type(dbus_msg);

#ifdef DEBUG
//    debug_raw_msg(dmsg, dbus_msg);
#endif

    argnum = 0;
    dbus_message_iter_init(dbus_msg, &iter);

    while ((type = dbus_message_iter_get_arg_type(&iter)) != DBUS_TYPE_INVALID) {

        void *arg;

        switch (type) {
            case (DBUS_TYPE_INT32):
                dmsg->arg_sig[argnum] = 'i';
                dbus_message_iter_get_basic(&iter, arg);
                dmsg->args[argnum++] = arg;
                break;

            case (DBUS_TYPE_STRING):
                dmsg->arg_sig[argnum] = 's';
                dbus_message_iter_get_basic(&iter, &arg);
                dmsg->args[argnum++] = arg;
                break; 

            default:
                break;
        }

        dbus_message_iter_next(&iter);
    }
    
    dmsg->arg_number = argnum;
    dbus_message_unref(dbus_msg);
    return ret;
}

static inline void append_variant(DBusMessageIter *iter, int type, void *data)
{
    DBusMessageIter sub;

    char *dbus_sig;
    int dbus_type;

    dbus_sig = NULL;
    dbus_type = DBUS_TYPE_INVALID;

    switch (type) {

        case ('i'):
            dbus_sig = "i";
            dbus_type = DBUS_TYPE_INT32;
            break;

        case ('u'):
            dbus_sig = "u";
            dbus_type = DBUS_TYPE_UINT32;
            break;

        case ('b'):
            dbus_sig = "b";
            dbus_type = DBUS_TYPE_BOOLEAN;
            break;

        case ('s'):
            dbus_sig = "s";
            dbus_type = DBUS_TYPE_STRING;
            break;

        case ('d'):
            dbus_sig = "d";
            dbus_type = DBUS_TYPE_DOUBLE;
            break;

        default:
            DBUS_BROKER_WARNING("Unrecognized DBus Variant <%d>", type);
            return;
    }

    if (dbus_type == DBUS_TYPE_INVALID)
        return;

    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                    (const char *) dbus_sig, &sub);

    if (type == 's')
        dbus_message_iter_append_basic(&sub, dbus_type, &data);
    else
        dbus_message_iter_append_basic(&sub, dbus_type, data);

    dbus_message_iter_close_container(iter, &sub);
}

/**
 * For every request being made to the dom0 dbus-server the domid needs to be
 * mapped to its corresponding UUID.  This is needed in order to find the VM
 * database policy to a given request.  The UUID's mapping to the domid can be
 * hashed but this function has to run once for each domain.
 *
 * @param domid the domain id to retrieve the uuid for.
 *
 * @return the uuid associated with the domain id or NULL
 */
char *get_uuid_from_domid(int domid)
{
    DBusMessage *msg;
    DBusConnection *conn;
    DBusMessageIter iter;
    char *path, *uuid;

    struct dbus_message dmsg = { .destination="com.citrix.xenclient.xenmgr",
                                 .path=DBUS_BASE_PATH,
                                 .interface="com.citrix.xenclient.xenmgr",
                                 .member="find_vm_by_domid",
                                 .args={&domid},
                                 .arg_number=1,
                                 .arg_sig={'i'},
                               };

    uuid = NULL;
    conn = create_dbus_connection();
    if (!conn)
        goto conn_error;

    msg = make_dbus_call(conn, &dmsg);
    if (!msg)
        goto conn_error;

    if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_ERROR)
        goto uuid_error;

    dbus_message_iter_init(msg, &iter);
    /* dbus message returns an "object-path" */
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
        goto uuid_error;

    dbus_message_iter_get_basic(&iter, &path);
    uuid = malloc(MAX_UUID);
    if (!uuid)
        goto uuid_error;

    /* cut off the "/vm/" of the path */
    strncpy(uuid, path + 4, MAX_UUID - 1);

uuid_error:
    dbus_message_unref(msg);

conn_error:

    return uuid;
}

/**
 * Facilitates in making raw dbus requests to the main dbus server.
 *
 * @param conn the dbus api connection object.
 * @param dmsg the dbus message object for the current message.
 *
 * @return the dbus api message object containing the reply.
 */
DBusMessage *make_dbus_call(DBusConnection *conn, struct dbus_message *dmsg)
{
    int i;
    DBusMessage *msg, *reply;
    DBusError error;
    DBusMessageIter iter;

    if (dmsg->destination)
        msg = dbus_message_new_method_call(dmsg->destination,
                                           dmsg->path,
                                           dmsg->interface,
                                           dmsg->member);
    else
        msg = dbus_message_new_signal(dmsg->path, dmsg->interface, dmsg->member);

    dbus_error_init(&error);
    dbus_message_iter_init_append(msg, &iter);

    for (i = 0; i < dmsg->arg_number; i++) {

        switch (dmsg->arg_sig[i]) {

            case ('s'):
                dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING,
                                               &(dmsg->args[i]));
                break;

            case ('u'):
                dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32,
                                                dmsg->args[i]);
                break;

            case ('i'):
                dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32,
                                                dmsg->args[i]);
                break;

            case ('b'):
                dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN,
                                                dmsg->args[i]);
                break;

            case ('v'):
                append_variant(&iter, dmsg->json_sig[i], dmsg->args[i]);
                break;

            default:
                DBUS_BROKER_ERROR("Failed Request <Invalid DBus Signature>");
                dbus_message_unref(msg);
                break;
        }
    }

    reply = dbus_connection_send_with_reply_and_block(conn, msg,
                                                      DBUS_REQ_TIMEOUT,
                                                     &error);
    dbus_message_unref(msg);

    if (reply == NULL) {
        DBUS_BROKER_WARNING("Failed Request <%s>", error.message);
        return NULL;
    }

    return reply;
}

/**
 * Helper function to facilitate requests to the xenclient database.
 *
 * @param conn the dbus api connection object.
 * @param arg a string associated with a field in the database.
 *
 * @return a null-terminated string associated for the database information
 * being requested or NULL 
 */
char *db_query(DBusConnection *conn, char *arg)
{
    char *reply;
    const char *buf;
    struct dbus_message db_msg;
    DBusMessage *msg;
    DBusMessageIter iter;

    reply = NULL;
    dbus_default(&db_msg, DBUS_READ, arg);
    msg = make_dbus_call(conn, &db_msg);
    if (!msg)
        return NULL;

    if (!dbus_message_iter_init(msg, &iter))
        goto free_msg;

    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
        goto free_msg;

    dbus_message_iter_get_basic(&iter, &buf);

    if (buf[0] == '\0')
        goto free_msg;

    reply = strdup(buf);
    if (!reply)
        DBUS_BROKER_WARNING("DBus Query Failed! %s", "");

free_msg:
    dbus_message_unref(msg);

    return reply;
}

/**
 * Requests all currently install virtual machines on a given host.
 *
 * @return the dbus api message object.
 */
DBusMessage *db_list(void)
{
    DBusConnection *conn;
    struct dbus_message dmsg;
    DBusMessage *vms;

    conn = create_dbus_connection();
    if (!conn)
        return NULL;

    dbus_default(&dmsg, DBUS_LIST, DBUS_VM_PATH);
    vms = make_dbus_call(conn, &dmsg);
    if (!vms && verbose_logging) {
        DBUS_BROKER_WARNING("DBus message return error <db-list> %s", "");
    } else if (vms && dbus_message_get_type(vms) == DBUS_MESSAGE_TYPE_ERROR) {
        if (verbose_logging)
            DBUS_BROKER_WARNING("DBus message return error <db-list> %s", "");
        dbus_message_unref(vms);
        vms = NULL;
    }

    dbus_connection_unref(conn);

    return vms;
}

/**
 * For any given dbus request, this function will retrieve its corresponding
 * introspection information.
 *
 * By matching up the method call being made with the ones listed in the
 * services' introspection data, we can examine what argument type the
 * service is expecting. Where as before relying on JSON to infer the type,
 * for instance JSON doesn't have uint32_t and would return int and the
 * method would fail expecting the former.
 *
 * @param jreq the json request object.
 *
 * @return the signature string for the json request or NULL.
 */
char *dbus_introspect(struct json_request *jreq)
{
    char *signature, *xml, *reply, *xmlbuf;
    DBusMessage *introspect;
    DBusMessageIter iter;

    struct dbus_message dmsg = { .destination=jreq->dmsg.destination,
                                 .interface=DBUS_INTRO_IFACE,
                                 .member=DBUS_INTRO_METH,
                                 .path=jreq->dmsg.path,
                                 .arg_number=0 };

    dbus_connection_flush(jreq->conn);

    signature = NULL;
    xml = malloc(DBUS_INTROSPECT_MAX);
    if (!xml)
        DBUS_BROKER_ERROR("Malloc Failed!");

    introspect = make_dbus_call(jreq->conn, &dmsg);

    if (!introspect) {
        DBUS_BROKER_WARNING("DBus Introspection message failed %s", "");
        goto xml_error;
    }

    if (dbus_message_get_type(introspect) == DBUS_MESSAGE_TYPE_ERROR) {
        DBUS_BROKER_WARNING("DBus Introspection message failed %s", "");
        goto msg_error;
    }

    dbus_message_iter_init(introspect, &iter);

    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
        DBUS_BROKER_WARNING("DBus Introspect return invalid type %s", "");
        goto msg_error;
    }

    dbus_message_iter_get_basic(&iter, &reply);
    strcpy(xml, reply);

    signature = calloc(1, XML_SIGNATURE_MAX);
    if (!signature)
        DBUS_BROKER_ERROR("Calloc Failed!");

    xmlbuf = strdup(xml);
    if (retrieve_xml_signature((const xmlChar *) xmlbuf, signature,
                                jreq->dmsg.interface, jreq->dmsg.member) < 1)
        signature[0] = '\0';

    free(xmlbuf);

msg_error:
    dbus_message_unref(introspect);

xml_error:
    free(xml);

    return signature;
}

struct dbus_link *add_dbus_signal(void)
{
    /* add extra field to show signals already subscribed to */
    struct dbus_link *head, *tail, *new_link;

    head = dlinks;
    new_link = malloc(sizeof *new_link);
    if (!new_link)
        DBUS_BROKER_ERROR("Malloc Failed!");

    if (!head) {
        new_link->next = NULL;
        new_link->prev = NULL;
        dlinks = new_link;
    } else {
        tail = head->prev;
        if (!tail) {
            head->prev = new_link;
            head->next = new_link;
            new_link->next = head;
            new_link->prev = head;
        } else {
            tail->next = new_link;
            head->prev = new_link;
            new_link->next = head;
            new_link->prev = tail;
        }
    }

    return new_link;
}

/**
 * Add a websockets signal to the running list.
 *
 * @param conn the dbus api connection object.
 * @param wsi the websockets api context object.
 */
void add_ws_signal(DBusConnection *conn, char *signal, struct lws *wsi)
{
    struct dbus_link *curr;
    curr = add_dbus_signal();
    curr->wsi = wsi;
    curr->dconn = conn;
    curr->signal_type = DBUS_SIGNAL_TYPE_CLIENT;
    curr->name = strdup(signal);
    signal_subscribers++;
    DBUS_BROKER_EVENT("WS add signal: <%zd>", signal_subscribers);
    curr->client_fd = signal_subscribers;
}

/**
 * Remove a websockets signal from the running list.
 *
 * @param link the current link to which remove from the list.
 */
void remove_dlink(struct dbus_link *link)
{
    if (link == dlinks) {
        free(link);
        dlinks = NULL;
    } else {
        link->next->prev = link->prev;
        link->prev->next = link->next;
        free(link);
    }
}

/**
 * Free's any UUID's from the uuid cache.
 */
void free_uuids(void)
{
    int i;
    for (i=0; i < UUID_CACHE_LIMIT; i++) {
        if (domain_uuids[i] != NULL)
            free(domain_uuids[i]);
    }
}

/**
 * Free's all websockets signal links from the running list.
 */
void free_dlinks(void)
{
    struct dbus_link *head, *curr;

    if (!dlinks)
        return;

    head = dlinks;
    curr = head->next;

    while (curr != head) {
        struct dbus_link *tmp;
        tmp = curr->next;
        free(curr);
        curr = tmp;
    }

    if (head)
        free(head);

    curr = NULL;
    head = NULL;
    dlinks = NULL;
}
