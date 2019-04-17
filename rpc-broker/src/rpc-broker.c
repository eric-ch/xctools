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
 * @file rpc-broker.c
 * @author Tim Konick <konickt@ainfosec.com>
 * @date March 4, 2019
 * @brief The main project file.
 *
 * All global data structures, event loops, and global state variables are
 * initialized here.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#include "rpc-broker.h"


uv_loop_t *rawdbus_loop;
bool reload_policy;


/**
 * Queries xenstore about whether a domain is a stubdom or not.
 *
 * @param domid the domain id to make query on.
 * 
 * @return the return boolean indicating whether the domain is a stubdom.
 */
bool is_stubdom(uint16_t domid)
{
    size_t len;
    bool domain_is_stubdom;

    len = 0;
    domain_is_stubdom = false;
     
#ifdef HAVE_XENSTORE
    struct xs_handle *xsh;
    char *path;
    void *ret;

    xsh = xs_open(XS_OPEN_READONLY);

    if (!xsh)
        return -1;

    path = xs_get_domain_path(xsh, domid);
    path = realloc(path, strlen(path) + XENSTORE_TARGET_LEN);
    strcat(path, XENSTORE_TARGET);

    ret = xs_read(xsh, XBT_NULL, path, &len);

    if (ret)
       free(ret);

    free(path);
    xs_close(xsh);
#endif
    if (len > 0)
        domain_is_stubdom = true;
    return domain_is_stubdom;
}

/**
 * Calculates the domain id for a given client.
 *
 * @param client is the file descriptor from the connection to get the domain
 * id from
 *
 * @return the domid.
 */
int get_domid(int client)
{
    int domain;

    domain = 0;
    /*
     * When using rpc-broker over ARGO, we want to be able to
     * firewall against domids. The ARGO interposer stores the
     * domid as follows:
     * sin.sin_addr.s_addr = htonl ((uint32_t) peer->domain | 0x1000000);
     * If we're not using ARGO, just return 0 for the domid.
     */
#ifdef HAVE_ARGO
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;

    client_addr_len = sizeof(client_addr);

    if (getpeername(client, &client_addr, &client_addr_len) < 0)
        DBUS_BROKER_WARNING("getpeername call failed <%s>", strerror(errno));
    else
        domain = ntohl(client_addr.sin_addr.s_addr) & ~0x1000000;
#endif

    return domain;
}

static void print_usage(void)
{
    printf("rpc-broker <flag> <argument>\n");
    printf("\t-b  [--bus-name=BUS]                    ");
    printf("A dbus bus name to make the connection to.\n");
    printf("\t-h  [--help]                            ");
    printf("Prints this usage description.\n");
    printf("\t-l  [--logging[=optional FILENAME]      ");
    printf("Enables logging to a default path, optionally set.\n");
    printf("\t-p  [--policy-file=FILENAME]            ");
    printf("Provide a policy file to run against.\n");
    printf("\t-r  [--raw-dbus=PORT]                   ");
    printf("Sets rpc-broker to run on given port as raw DBus.\n");
    printf("\t-v  [--verbose]                         ");
    printf("Adds extra information (run with logging).\n");
    printf("\t-w  [--websockets=PORT]                 ");
    printf("Sets rpc-broker to run on given address/port as websockets.\n");
}

static void sigint_handler(int signal)
{
    DBUS_BROKER_WARNING("<received signal interrupt> %s", "");
    free_dlinks();
    free_policy();

    if (ring)
        lws_ring_destroy(ring);

    if (rawdbus_loop) {
        uv_stop(rawdbus_loop);
        uv_loop_close(rawdbus_loop);
        free(rawdbus_loop);
    }

    exit(0);
}

static void sighup_handler(int signal)
{
    DBUS_BROKER_EVENT("Re-loading policy %s", "");
    reload_policy = true;
}

static void parse_server_signal(DBusMessage *msg)
{
    char *str;
    int msgtype;
    int current_type;
    DBusMessageIter iter;

    msgtype = dbus_message_get_type(msg);
    if (msgtype == DBUS_MESSAGE_TYPE_ERROR)
        return;

    dbus_message_iter_init(msg, &iter);
    while ((current_type = dbus_message_iter_get_arg_type (&iter)) != DBUS_TYPE_INVALID) {
        if (current_type == DBUS_TYPE_STRING) {
            dbus_message_iter_get_basic(&iter, &str);
            if (verbose_logging)
                DBUS_BROKER_EVENT("Xenmgr msg: (%s)", str); 
            reload_policy = true;
        } 
        dbus_message_iter_next (&iter);
    }
}

static void parse_client_signal(DBusMessage *msg, struct lws *wsi)
{
    char *reply;
    struct json_response *jrsp;

    jrsp = init_jrsp();
    jrsp->response_to[0] = '\0';
    snprintf(jrsp->type, JSON_REQ_ID_MAX - 1, "%s", JSON_SIG);

    load_json_response(msg, jrsp);

    jrsp->interface = dbus_message_get_interface(msg);
    jrsp->member = dbus_message_get_member(msg);
    jrsp->path = dbus_message_get_path(msg);

    reply = prepare_json_reply(jrsp);

    if (!reply)
        goto free_jrsp;

    lws_callback_on_writable(wsi);
    lws_ring_insert(ring, reply, 1);
    free(reply);

free_jrsp:
        free(jrsp);
}

/*
 * Cycle through linked-list of current dbus-signals being subscribed to.
 * If there are any signals queued up, start the exchange of communication.
 */
static void service_ws_signals(void)
{
    bool remove_link;
    struct dbus_link *curr;
    DBusMessage *msg;

    if (dlinks == NULL)
        return;

    curr = dlinks;
    remove_link = false;

    struct timespec t;
    //clock_gettime(CLOCK_REALTIME, &t);
    //DBUS_BROKER_EVENT("WS Service Entry <%llu %llu>", t.tv_sec, t.tv_nsec);

    do {
        msg = NULL;

        if (!curr->dconn || !dbus_connection_get_is_connected(curr->dconn)) {
//            remove_link = true;
            goto next_link;
        } 
        /*
        int connfd;
        if (!dbus_connection_get_socket(curr->dconn, &connfd)) {
            DBUS_BROKER_WARNING("Websocket Signal Connection Failed %s", "")
            goto next_link;
        }
        // set the FD to O_NONBLOCK?
        */
        switch (dbus_connection_get_dispatch_status(curr->dconn)) {

            case (DBUS_DISPATCH_DATA_REMAINS):
                DBUS_BROKER_EVENT("Message in Queue%s", "");
                break;
            case (DBUS_DISPATCH_COMPLETE):
                break;
            case (DBUS_DISPATCH_NEED_MEMORY):
                DBUS_BROKER_EVENT("Need Memory%s", "");
                break;
            default:
                break;
        }

        dbus_connection_read_write(curr->dconn, 1);
        msg = dbus_connection_pop_message(curr->dconn);
        //DBUS_BROKER_EVENT("WS Signal <%d>", curr->client_fd);
        if (!msg)
            goto next_link;
        
        if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
            goto unref_msg;
        switch (curr->signal_type) {

            case (DBUS_SIGNAL_TYPE_SERVER):
                parse_server_signal(msg);
                break;

            case (DBUS_SIGNAL_TYPE_CLIENT): {
                parse_client_signal(msg, curr->wsi);
                clock_gettime(CLOCK_REALTIME, &t);
            }
                break;

            default:
                if (verbose_logging)
                    DBUS_BROKER_WARNING("Unknown dbus-signal type %s", "");
                break;
        }

unref_msg:
        dbus_message_unref(msg);

next_link:
        curr = curr->next;

        if (remove_link) {
            remove_dlink(curr->prev);
            remove_link = false;
            signal_subscribers--;
            DBUS_BROKER_EVENT("WS rm signal: <%zd>", signal_subscribers);
        }

    } while (curr && curr != dlinks);

    //clock_gettime(CLOCK_REALTIME, &t);
    //DBUS_BROKER_EVENT("WS Service Exit <%llu %llu>", t.tv_sec, t.tv_nsec);
}

static void run_websockets(struct dbus_broker_args *args)
{
    struct lws_context *ws_context;
    struct dbus_link *xenmgr_signal;

    ws_context = NULL;
    signal_subscribers = 0;
    if ((ws_context = create_ws_context(args->port)) == NULL)
        DBUS_BROKER_ERROR("WebSockets-Server");

    xenmgr_signal = add_dbus_signal();
    xenmgr_signal->dconn = create_dbus_connection();
    dbus_bus_add_match(xenmgr_signal->dconn, XENMGR_SIGNAL_SERVICE, NULL); 
    xenmgr_signal->signal_type = DBUS_SIGNAL_TYPE_SERVER;
    DBUS_BROKER_EVENT("Websockets building policy...%s", "");

    dbus_broker_policy = build_policy(args->rule_file);
    DBUS_BROKER_EVENT("<WebSockets-Server has started listening> [Port: %d]",
                        args->port);

    while (dbus_broker_running) {

        if (reload_policy) {
            free_policy();
            dbus_broker_policy = build_policy(args->rule_file);
            reload_policy = false;
        }

        lws_service(ws_context, WS_LOOP_TIMEOUT);
        service_ws_signals();
    }

    if (ring)
        lws_ring_destroy(ring);

    if (ws_context)
        lws_context_destroy(ws_context);
}

static void close_client_rawdbus(uv_handle_t *handle)
{
    struct raw_dbus_conn *conn;

    conn = (struct raw_dbus_conn *) handle->data;
    close(conn->receiver);
    uv_unref(handle);

    if (conn)
        free(conn);

    conn = NULL;
}

static void close_server_rawdbus(uv_handle_t *handle)
{
    struct dbus_broker_server *server;
    server = (struct dbus_broker_server *) handle->data;
    close(server->dbus_socket);
    uv_unref(handle);
}

static void service_rdconn_cb(uv_poll_t *handle, int status, int events)
{
    int ret, total;
    struct raw_dbus_conn *conn;

    conn = (struct raw_dbus_conn *) handle->data;
    ret = 0;
    total = 0;

    if (events & UV_READABLE) {
        while ((ret = exchange(conn->receiver, conn->sender, 
                               conn->client_domain, conn->is_client)) != 0) 
            total += ret;
        if (total <= 0)
            uv_close((uv_handle_t *) handle, close_client_rawdbus);
    }
}

static void init_rawdbus_conn(uv_loop_t *rawdbus_loop, int sender,
                              int receiver, int domain, bool is_client)
{
    struct raw_dbus_conn *conn;

    conn = malloc(sizeof *conn);
    if (!conn)
        DBUS_BROKER_ERROR("Malloc Failed!");

    conn->sender = sender;
    conn->receiver = receiver;
    conn->client_domain = domain;
    conn->is_client = is_client;
    conn->handle.data = conn;
    uv_poll_init(rawdbus_loop, &conn->handle, conn->receiver);
    uv_poll_start(&conn->handle, UV_READABLE | UV_DISCONNECT,
                   service_rdconn_cb);
}

static void close_xenmgr_signal(uv_handle_t *handle)
{
    struct xenmgr_signal *xensig = (struct xenmgr_signal *) handle->data;
    close(xensig->signal_fd);
    uv_unref(handle);
}

static void xenmgr_signal(uv_poll_t *handle, int status, int events)
{
    struct xenmgr_signal *xensig = (struct xenmgr_signal *) handle->data;
    DBusMessage *msg = dbus_connection_pop_message(xensig->conn);

    if (!msg) {
        uv_close((uv_handle_t *) handle, close_xenmgr_signal);
        return;
    }

    parse_server_signal(msg);
}

static void init_xenmgr_signal(uv_loop_t *loop)
{
    struct xenmgr_signal *xensig = calloc(1, sizeof *xensig);
    char *crt = "type='signal',interface='com.citrix.xenclient.xenmgr',member='vm_state_changed'";
    xensig->conn = create_dbus_connection(); 
    dbus_bus_add_match(xensig->conn, crt, NULL); 

    if (!dbus_connection_get_socket(xensig->conn, &xensig->signal_fd))
        DBUS_BROKER_WARNING("Xenmgr Signal Subscription Failed! %s", "");
    else {
        xensig->handle.data = xensig;
        uv_poll_init(loop, &xensig->handle, xensig->signal_fd);
        uv_poll_start(&xensig->handle, UV_READABLE | UV_DISCONNECT,
                       xenmgr_signal);
    }        
}

static void service_rawdbus_server(uv_poll_t *handle, int status, int events)
{
    struct dbus_broker_server *dbus_server;
    uv_loop_t *loop;
    int client, server, domain;

    dbus_server = (struct dbus_broker_server *) handle->data;
    loop = dbus_server->mainloop;
    if (events & UV_READABLE) {
	        socklen_t clilen = sizeof(dbus_server->peer);
	        client = accept(dbus_server->dbus_socket,
                           (struct sockaddr *) &dbus_server->peer, &clilen);
            server = connect_to_system_bus();
            domain = get_domid(client);
            init_rawdbus_conn(loop, server, client, domain, true);
            init_rawdbus_conn(loop, client, server, domain, false);
    } else if (events & UV_DISCONNECT) {
        dbus_broker_running = 0;
        uv_close((uv_handle_t *) handle, close_server_rawdbus);
    }
}

static void run_rawdbus(struct dbus_broker_args *args)
{
    struct dbus_broker_server server;
    if (start_server(&server, args->port) < 0)
        DBUS_BROKER_ERROR("DBus server failed to start!");

    DBUS_BROKER_EVENT("<Server has started listening> [Port: %d]", args->port);

    dbus_broker_policy = build_policy(args->rule_file);

    rawdbus_loop = malloc(sizeof *rawdbus_loop);
    if (!rawdbus_loop)
        DBUS_BROKER_ERROR("Malloc Failed!");

    uv_loop_init(rawdbus_loop);

    uv_poll_init(rawdbus_loop, &server.handle, server.dbus_socket);
    uv_poll_start(&server.handle, UV_READABLE | UV_DISCONNECT,
                   service_rawdbus_server);

    server.mainloop = rawdbus_loop;
    server.port = args->port;
    server.handle.data = &server;
    init_xenmgr_signal(rawdbus_loop);

    while (dbus_broker_running) {
        uv_run(rawdbus_loop, UV_RUN_ONCE);
        if (reload_policy) {
            free_policy();
            dbus_broker_policy = build_policy(args->rule_file);
            reload_policy = false;
        }
    }

    uv_stop(rawdbus_loop);
    uv_loop_close(rawdbus_loop);
    free(rawdbus_loop);
}

int main(int argc, char *argv[])
{
    const char *dbus_broker_opt_str = "b:hl::p:r:vw:";

    struct option dbus_broker_opts[] = {
        { "bus-name",    required_argument,   0, 'b' },
        { "help",        no_argument,         0, 'h' },
        { "logging",     optional_argument,   0, 'l' },
        { "policy-file", required_argument,   0, 'p' },
        { "raw-dbus",    required_argument,   0, 'r' },
        { "verbose",     no_argument,         0, 'v' },
        { "websockets",  required_argument,   0, 'w' },
        {  0,            0,        0,         0      }
    };

    int opt, option_index;
    void (*mainloop)(struct dbus_broker_args *args);

    char *websockets, *raw_dbus;
    char *logging_file, *bus_file, *policy_file;
    uint32_t port;
    bool proto, logging;

    logging = false;
    verbose_logging = false;

    bus_file = NULL;
    raw_dbus = NULL;
    websockets = NULL;
    logging_file = "";
    policy_file  = RULES_FILENAME;

    proto = false;

    dbus_broker_opt_str = "b:hl::p:r:vw:";

    while ((opt = getopt_long(argc, argv, dbus_broker_opt_str,
                              dbus_broker_opts, &option_index)) != -1) {

        switch (opt) {

            case ('b'):
                bus_file = optarg;
                break;

            case ('l'):
                logging = true;
                if (optarg)
                    logging_file = optarg;
                break;

            case ('p'):
                policy_file = optarg;
                break;

            case ('r'):
                if (proto)
                    goto conn_type_error;
                raw_dbus = optarg;
                proto = true;
                break;

            case ('v'):
                verbose_logging = true;
                break;

            case ('w'):
                if (proto)
                    goto conn_type_error;
                websockets = optarg;
                proto = true;
                break;

            case ('h'):
            case ('?'):
                print_usage();
                exit(0);
                break;
        }
    }

    errno = 0;
    if (raw_dbus) {
        port = strtol(raw_dbus, NULL, 0);
        if (errno != 0)
            DBUS_BROKER_ERROR("Invalid raw-dbus port");
        mainloop = run_rawdbus;
    } else if (websockets) {
        port = strtol(websockets, NULL, 0);
        if (errno != 0)
            DBUS_BROKER_ERROR("Invalid websockets port");
        mainloop = run_websockets;
    } else
        goto conn_type_error;

    struct dbus_broker_args args = {
        .logging=logging,
        .verbose=verbose_logging,
        .bus_name=bus_file,
        .logging_file=logging_file,
        .rule_file=policy_file,
        .port=port,
    };

    struct sigaction sa_sigint = { .sa_handler=sigint_handler };

    if (sigaction(SIGINT, &sa_sigint, NULL) < 0)
        DBUS_BROKER_ERROR("sigaction");

    struct sigaction sa_sighup = { .sa_handler=sighup_handler };

    if (sigaction(SIGHUP, &sa_sighup, NULL) < 0)
        DBUS_BROKER_ERROR("sigaction");

    dbus_broker_running = 1;
    dlinks = NULL;
    rawdbus_loop = NULL;
    ring = NULL;
    reload_policy = false;
    CACHE_INIT(domain_uuids, UUID_CACHE_LIMIT);
    mainloop(&args);

    free_policy();
    free_dlinks();
    free_uuids();

    return 0;

conn_type_error:

    printf("Must supply at least one (and no more than one) connection type.\n");
    print_usage();

    return 0;
}

