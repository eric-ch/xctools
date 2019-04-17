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
 * @file header for main source file.
 * @author Tim Konick <konickt@ainfosec.com>
 * @date March 4, 2019
 * @brief Main header declarations 
 *
 * Functions, state variables, and objects for running the event loops.  There
 * are also definitions for misc. utility functions. 
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dbus/dbus.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <uv.h>

#ifdef HAVE_XENSTORE
#include <xenstore.h>
#endif

#include "rpc-dbus.h"
#include "rpc-json.h"
#include "policy.h"
#include "signature.h"
#include "websockets.h"

//
#define DEBUG 1
//
#define DBUS_BROKER_ERROR(call)                                       \
    do {                                                              \
        openlog(NULL, LOG_PERROR, 0);                                 \
        syslog(LOG_ERR, "%s %s %s", call, __func__, strerror(errno)); \
        closelog();                                                   \
        exit(0);                                                      \
    } while ( 1 )                                                     \

#define DBUS_LOG(type, fmt, ...)                                      \
    ({                                                                \
        char *buf = NULL;                                             \
        if (asprintf(&buf, fmt, __VA_ARGS__) < 0)                     \
            exit(0);                                                  \
        syslog(type, "%s", buf);                                      \
        free(buf);                                                    \
    })                                                                \

#define DBUS_BROKER_WARNING(fmt, ...) DBUS_LOG(LOG_WARNING, fmt, __VA_ARGS__)
#define DBUS_BROKER_EVENT(fmt, ...)   DBUS_LOG(LOG_INFO, fmt, __VA_ARGS__)

#define DBUS_REQ_ARG(buf, fmt, ...)               \
    ({                                            \
        if (asprintf(&buf, fmt, __VA_ARGS__) < 0) \
            exit(0);                              \
    })                                            \

/* DBus-Broker server */
#define BROKER_DEFAULT_PORT 5555
#define BROKER_UI_PORT      8080

#define UUID_CACHE_LIMIT 1024

#define CACHE_INIT(cache, limit)        \
({                                      \
    int i;                              \
    for (i=0; i < limit; i++)           \
        cache[i] = NULL;                \
})                                      \

/**
 * @brief object that holds the main dbus server connection state.
 */
struct dbus_broker_server {
    int dbus_socket;
    int port;
    struct sockaddr_in addr;
    struct sockaddr_in peer;
    uv_loop_t *mainloop;
    uv_poll_t handle;
};

bool verbose_logging;
int dbus_broker_running;
char *domain_uuids[UUID_CACHE_LIMIT];

/**
 * @brief contains the command line arguments passed upon invocation.
 */
struct dbus_broker_args {
    bool logging;
    bool verbose;
    int port;
    const char *bus_name;
    const char *logging_file;
    const char *rule_file;
};

/**
 * @brief object that's created upon each request made to connect to the actaul
 * dbus.   
 */
struct raw_dbus_conn {
    int receiver;
    int sender;
    bool is_client;
    uint32_t client_domain;
    uv_poll_t handle;
};

/**
 * @brief object to encapsulate data thats used to track xenmgr service signals
 */
struct xenmgr_signal {
    DBusConnection *conn;
    int signal_fd;
    uv_poll_t handle;
};

/* rpc-broker.c */
bool is_stubdom(uint16_t domid);

int get_domid(int client);

void free_uuids(void);

/* src/msg.c */
bool is_request_allowed(struct dbus_message *dmsg, bool is_client, int domid);

int exchange(int rsock, int ssock, uint16_t domid, bool is_client);
