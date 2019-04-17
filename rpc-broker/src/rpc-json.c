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
 * @file rpc-json.c
 * @author Tim Konick
 * @date March 4, 2019
 * @brief JSON request handling
 *
 * All websocket requests are made using the JSON format.  All the loading
 * and unloading of the JSON objects is done through the functions here.
 * Then going the other way as well, the conversion from dbus api objects
 * into websockets request objects.
 */

#include "rpc-broker.h"


/**
 * Initializes a JSON response object.
 */
struct json_response *init_jrsp(void)
{
    struct json_response *jrsp;
    jrsp = calloc(1, sizeof *jrsp);
    if (!jrsp)
        DBUS_BROKER_ERROR("Calloc Failed!");

    jrsp->args = json_object_new_array();
    memcpy(jrsp->type, JSON_RESP, strlen(JSON_RESP) + 1);

    return jrsp;
}

/**
 * Takes a JSON request object, makes a dbus request and converts into a 
 * JSON response object.  
 *
 * @param jreq a tokenized object for the request being made.   
 *
 * @return a JSON response object or NULL.
 */
struct json_response *make_json_request(struct json_request *jreq)
{
    struct json_response *jrsp;
    DBusConnection *conn;
    DBusMessage *msg;
    const char *busname;
    char *err;

    jrsp = init_jrsp();
    conn = jreq->conn;
    dbus_connection_flush(conn);
    jrsp->id = jreq->id;

    if (jreq->dmsg.member && !strcmp(jreq->dmsg.member, "Hello")) {

        busname = dbus_bus_get_unique_name(conn);

        if (!busname)
            DBUS_BROKER_ERROR("DBus refused busname");

        snprintf(jrsp->response_to, JSON_REQ_ID_MAX - 1, "%d", jreq->id);
        memcpy(jrsp->arg_sig, "s", 2);
        json_object_array_add(jrsp->args, json_object_new_string(busname));
        return jrsp;
    }

    snprintf(jrsp->response_to, JSON_REQ_ID_MAX - 1, "%d", jreq->id);
    msg = make_dbus_call(conn, &(jreq->dmsg));

    if (!msg || dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_ERROR) {
        DBUS_REQ_ARG(err, "<Destination=%s Path=%s Interface=%s Member=%s>",
                     jreq->dmsg.destination, jreq->dmsg.path,
                     jreq->dmsg.interface, jreq->dmsg.member);
        DBUS_BROKER_WARNING("response to <%d> request failed %s", jreq->id, err);

        if (msg) {
            DBUS_BROKER_WARNING("DBUS: %s", dbus_message_get_error_name(msg));
            dbus_message_unref(msg);
        }

        free(err);
        json_object_put(jrsp->args);
        free(jrsp);
        return NULL;
    }

    load_json_response(msg, jrsp);
    dbus_message_unref(msg);

    return jrsp;
}

static void append_dbus_message_arg(int type, int idx, void **args,
                                    struct json_object *jarg)
{
    /* 
     * todo: have the "argument" array -> `void **args`
     *       be set-up as an array of `struct arg`
     *       and these types won't need to be declared
     *      (possibly adding union-type in the `struct arg`)
     */

    switch (type) {

        case ('b'): {
            int json_bool = json_object_get_boolean(jarg);
            args[idx] = malloc(sizeof(int));
            memcpy(args[idx], (void *) &json_bool, sizeof(int));
            break;
        }

        case ('u'):
        case ('i'): {
            int json_int = json_object_get_int(jarg);
            args[idx] = malloc(sizeof(int));
            memcpy(args[idx], (void *) &json_int, sizeof(int));
            break;
        }

        case ('d'): {
            double json_double = json_object_get_double(jarg);
            args[idx] = malloc(sizeof(double));
            memcpy(args[idx], (void *) &json_double, sizeof(double));
            break;
        }

        case ('s'): {
            const char *json_str = json_object_get_string(jarg);
            if (!json_str)
                json_str = "";
            args[idx] = strdup(json_str);
            break;
        }

        case ('v'): {
            int jtype = json_object_get_type(jarg);
            type = json_dbus_types[jtype];
            append_dbus_message_arg(type, idx, args, jarg);
            break;
        }

        default:
            break;
    }
}

static const char *get_json_str_obj(struct json_object *jobj, char *field)
{
    struct json_object *jfield;

    if (!json_object_object_get_ex(jobj, field, &jfield))
        return NULL;

    return strdup(json_object_get_string(jfield));
}

/**
 * Loads a JSON response object based of a dbus api message object and its
 * corresponding arguments. 
 *
 * @param msg a dbus api object with the reply message
 * @param jrsp the JSON response object to be initialized
 */
void load_json_response(DBusMessage *msg, struct json_response *jrsp)
{
    DBusMessageIter iter, sub;
    char *sig;
    struct json_object *args;

    dbus_message_iter_init(msg, &iter);

    sig = dbus_message_iter_get_signature(&iter);
    snprintf(jrsp->arg_sig, DBUS_MAX_ARG_LEN - 1, "%s", sig);
    dbus_free(sig);

    args = jrsp->args;

    if (jrsp->arg_sig && jrsp->arg_sig[0] == 'a') {

        dbus_message_iter_recurse(&iter, &sub);
        iter = sub;
        /*
         * This accomodates the legacy code in `rpc-proxy` where the
         * signatures are being mis-handled and thus the UI is excpecting
         * the malformed dbus responses.
         */
        switch (jrsp->arg_sig[1]) {
            case 'a':
            case 'i':
            case 's':
            case 'o': {
                struct json_object *array = json_object_new_array();
                json_object_array_add(jrsp->args, array);
                args = array;
                break;
            }

            default:
                break;
        }
    }

    parse_signature(args, NULL, &iter);
}

static signed int parse_json_args(struct json_object *jarray,
                                  struct json_request *jreq)
{
    char *signature, *sigptr;
    size_t array_length;
    int i, jtype;
    struct json_object *jarg;

    /* supports the removal of network-daemon/slave */
    if (!jreq->dmsg.destination && jreq->dmsg.type) {
        signature = malloc(3);
        if (!signature)
            DBUS_BROKER_ERROR("Malloc Failed!");
        snprintf(signature, 3, "uu");
    } else
        signature = dbus_introspect(jreq);

    if (!signature) {
        DBUS_BROKER_WARNING("dbus-introspect %s", "");
        jreq->dmsg.arg_number = 0;
        return -1;
    }

    strncpy(jreq->dmsg.arg_sig, signature, DBUS_MAX_ARG_LEN - 1);
    array_length = json_object_array_length(jarray);
    jreq->dmsg.arg_number = array_length;
    sigptr = signature;

    for (i = 0; i < array_length; i++) {

        jarg = json_object_array_get_idx(jarray, i);
        jtype = json_object_get_type(jarg);

        if (jtype == json_type_null) {
            jreq->dmsg.args[i] = strdup("");
            continue;
        }

        jreq->dmsg.json_sig[i] = json_dbus_types[jtype];
        append_dbus_message_arg(*sigptr, i, jreq->dmsg.args, jarg);
        sigptr++;
    }

    free(signature);

    return 0;
}

/**
 * Takes raw bytes provided by a websockets request and load them into a JSON
 * request object.
 *
 * @param raw_json_req raw bytes from a websockets request.
 * 
 * @return a JSON request object or NULL.
 */
struct json_request *convert_json_request(char *raw_json_req)
{
    struct json_request *jreq;
    struct json_object *jobj, *jarray, *jint;

    jobj = json_tokener_parse(raw_json_req);

    if (!jobj) {
        DBUS_BROKER_WARNING("<Error parsing json-request> %s", raw_json_req);
        return NULL;
    }

    jreq = malloc(sizeof *jreq);
    if (!jreq) {
        DBUS_BROKER_WARNING("<Malloc Failed! %s", "");
        return NULL;
    }

    memset(&jreq->dmsg, 0, sizeof(jreq->dmsg));
    jreq->dmsg.destination = get_json_str_obj(jobj, "destination");
    /* supports the removal of network-daemon/slave */
    if (!jreq->dmsg.destination) {
        jreq->dmsg.type = get_json_str_obj(jobj, "type");
    } else
        jreq->dmsg.type = NULL;

    if (!(jreq->dmsg.interface = get_json_str_obj(jobj, "interface")) ||
        !(jreq->dmsg.path = get_json_str_obj(jobj, "path"))           ||
        !(jreq->dmsg.member = get_json_str_obj(jobj, "method")))
        goto request_error;

    jreq->conn = create_dbus_connection();
    jarray = NULL;
    if (!json_object_object_get_ex(jobj, "args", &jarray))
        goto request_error;

    if (parse_json_args(jarray, jreq) < 0)
        goto request_error;

    jint = NULL;
    if (!json_object_object_get_ex(jobj, "id", &jint))
        goto request_error;

    jreq->id = json_object_get_int(jint);

    /* json free's recursively on objects */
    json_object_put(jobj);

    return jreq;

request_error:

    DBUS_BROKER_WARNING("<Error json-request> %s", raw_json_req);
    free_json_request(jreq);
    json_object_put(jobj);

    return NULL;
}

/**
 * Frees JSON request objects.
 *
 * @param jreq the request to be freed.
 */
void free_json_request(struct json_request *jreq)
{
    int i;

    for (i = 0; i < jreq->dmsg.arg_number; i++) {
        if (jreq->dmsg.args[i]) {
            free(jreq->dmsg.args[i]);
            jreq->dmsg.args[i] = NULL;
        }
    }

    if (jreq->dmsg.destination)
        free((char *) (jreq->dmsg.destination));
    if (jreq->dmsg.interface)
        free((char *) (jreq->dmsg.interface));
    if (jreq->dmsg.path)
        free((char *) (jreq->dmsg.path));
    if (jreq->dmsg.member)
        free((char *) (jreq->dmsg.member));

    free(jreq);
}

/**
 * Takes a JSON response object and converts it into a JSON api response
 * object.
 *
 * @param jrsp the JSON response object 
 *
 * @return JSON api `json_object`
 */ 
struct json_object *convert_dbus_response(struct json_response *jrsp)
{
    struct json_object *jobj;

    jobj = json_object_new_object();
    json_object_object_add(jobj, "id", json_object_new_int(jrsp->id));
    json_object_object_add(jobj, "type", json_object_new_string(jrsp->type));

    if (jrsp->response_to[0] != '\0') {
        json_object_object_add(jobj, "response-to",
                               json_object_new_string(jrsp->response_to));
    } else {
        json_object_object_add(jobj, "interface",
                               json_object_new_string(jrsp->interface));
        json_object_object_add(jobj, "path",
                               json_object_new_string(jrsp->path));
        json_object_object_add(jobj, "member",
                               json_object_new_string(jrsp->member));
    }

    json_object_object_add(jobj, "args", jrsp->args);
    return jobj;
}

/**
 * Utility function to add fields to JSON api object.
 *
 * @param args JSON api object to add.
 * @param key JSON api field identifier to add to.
 * @param jobj JSON api main object receiving the arguments. 
 */
void add_jobj(struct json_object *args, char *key, struct json_object *jobj)
{
    if (!key)
        json_object_array_add(args, jobj);
    else
        json_object_object_add(args, key, jobj);
}

