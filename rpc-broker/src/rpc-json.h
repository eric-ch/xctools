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
 * @file rpc-json.h
 * @author Tim Konick <konickt@ainfosec.com>
 * @date March 4, 2019
 * @brief JSON handling declarations.
 *
 * Functions, data structures, and global variables for handling any JSON
 * requests being made.
 */
#include <json.h>


/**
 * @brief contains JSON request connection data.
 */
struct json_request {
    uint32_t id;
    DBusConnection *conn;
    struct lws *wsi;
    struct dbus_message dmsg;
};

#define JSON_REQ_ID_MAX 16
#define JSON_TYPE_MAX   16
#define JSON_REQ_MAX   256

/**
 * @brief contains JSON response data.
 */
struct json_response {
    uint32_t id;
    const char *path;
    const char *interface;
    const char *member;
    char response_to[JSON_REQ_ID_MAX];
    char type[JSON_TYPE_MAX];
    char arg_sig[DBUS_MAX_ARG_LEN];
    struct json_object *args;
};

static const char json_dbus_types[] = {
    [json_type_boolean] = 'b',
    [json_type_double]  = 'd',
    [json_type_int]     = 'i',
    [json_type_string]  = 's'
};


// src/rpc-json.c
struct json_response *init_jrsp(void);

struct json_response *make_json_request(struct json_request *jreq);

void load_json_response(DBusMessage *msg, struct json_response *jrsp);

struct json_request *convert_json_request(char *raw_json_req);

struct json_object *convert_dbus_response(struct json_response *jrsp);

void add_jobj(struct json_object *args, char *key, struct json_object *jobj);

void free_json_request(struct json_request *jreq);

#define JSON_RESP "response"
#define JSON_SIG  "signal"
