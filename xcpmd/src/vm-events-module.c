/*
 * vm-events-module.c
 *
 * XCPMD module that monitors VM state changes.
 *
 * Copyright (c) 2015 Assured Information Security, Inc.
 *
 * Author:
 * Jennifer Temkin <temkinj@ainfosec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
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

#include <stdlib.h>
#include <stdio.h>
#include "project.h"
#include "xcpmd.h"
#include "modules.h"
#include "rules.h"
#include "vm-events-module.h"
#include "vm-utils.h"

/**
 * This module listens for any VM state changes on DBus.
 * Consequently, this module must be loaded after xcdbus_conn is established.
 */

//Function prototypes
bool any_vm_creating(struct ev_wrapper * event, struct arg_node * args);
bool any_vm_stopping(struct ev_wrapper * event, struct arg_node * args);
bool any_vm_rebooting(struct ev_wrapper * event, struct arg_node * args);
bool any_vm_running(struct ev_wrapper * event, struct arg_node * args);
bool any_vm_stopped(struct ev_wrapper * event, struct arg_node * args);
bool any_vm_paused(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_uuid_creating(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_uuid_stopping(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_uuid_rebooting(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_uuid_running(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_uuid_stopped(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_uuid_paused(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_name_creating(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_name_stopping(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_name_rebooting(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_name_running(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_name_stopped(struct ev_wrapper * event, struct arg_node * args);
bool vm_with_name_paused(struct ev_wrapper * event, struct arg_node * args);

DBusHandlerResult dbus_signal_handler(DBusConnection * connection, DBusMessage * dbus_message, void * user_data);


//Private data structures
struct event_data_row {
    char * name;
    bool is_stateless;
    enum arg_type value_type;
    union arg_u reset_value;
    unsigned int index;
};

struct cond_table_row {
    char * name;
    bool (* func)(struct ev_wrapper *, struct arg_node *);
    char * prototype;
    char * pretty_prototype;
    unsigned int event_index;
    void (* on_instantiate)(struct condition *);
};


//Private data
static struct event_data_row event_data[] = {
    {"event_vm_creating"    , IS_STATELESS  , ARG_STR , { .str = "" } , EVENT_VM_CREATING  } ,
    {"event_vm_stopping"    , IS_STATELESS  , ARG_STR , { .str = "" } , EVENT_VM_STOPPING  } ,
    {"event_vm_rebooting"   , IS_STATELESS  , ARG_STR , { .str = "" } , EVENT_VM_REBOOTING } ,
    {"event_vm_running"     , IS_STATELESS  , ARG_STR , { .str = "" } , EVENT_VM_RUNNING   } ,
    {"event_vm_stopped"     , IS_STATELESS  , ARG_STR , { .str = "" } , EVENT_VM_STOPPED   } ,
    {"event_vm_paused"      , IS_STATELESS  , ARG_STR , { .str = "" } , EVENT_VM_PAUSED    }
};

static struct cond_table_row condition_data[] = {
    {"whenAnyVmCreating"   , any_vm_creating         , "n" , "void"        , EVENT_VM_CREATING  , NULL } ,
    {"whenAnyVmStopping"   , any_vm_stopping         , "n" , "void"        , EVENT_VM_STOPPING  , NULL } ,
    {"whenAnyVmRebooting"  , any_vm_rebooting        , "n" , "void"        , EVENT_VM_REBOOTING , NULL } ,
    {"whenAnyVmRunning"    , any_vm_running          , "n" , "void"        , EVENT_VM_RUNNING   , NULL } ,
    {"whenAnyVmStopped"    , any_vm_stopped          , "n" , "void"        , EVENT_VM_STOPPED   , NULL } ,
    {"whenAnyVmPaused"     , any_vm_paused           , "n" , "void"        , EVENT_VM_PAUSED    , NULL } ,
    {"whenVmUuidCreating"  , vm_with_uuid_creating   , "s" , "string uuid" , EVENT_VM_CREATING  , NULL } ,
    {"whenVmUuidStopping"  , vm_with_uuid_stopping   , "s" , "string uuid" , EVENT_VM_STOPPING  , NULL } ,
    {"whenVmUuidRebooting" , vm_with_uuid_rebooting  , "s" , "string uuid" , EVENT_VM_REBOOTING , NULL } ,
    {"whenVmUuidRunning"   , vm_with_uuid_running    , "s" , "string uuid" , EVENT_VM_RUNNING   , NULL } ,
    {"whenVmUuidStopped"   , vm_with_uuid_stopped    , "s" , "string uuid" , EVENT_VM_STOPPED   , NULL } ,
    {"whenVmUuidPaused"    , vm_with_uuid_paused     , "s" , "string uuid" , EVENT_VM_PAUSED    , NULL } ,
    {"whenVmCreating"      , vm_with_name_creating   , "s" , "string name" , EVENT_VM_CREATING  , NULL } ,
    {"whenVmStopping"      , vm_with_name_stopping   , "s" , "string name" , EVENT_VM_STOPPING  , NULL } ,
    {"whenVmRebooting"     , vm_with_name_rebooting  , "s" , "string name" , EVENT_VM_REBOOTING , NULL } ,
    {"whenVmRunning"       , vm_with_name_running    , "s" , "string name" , EVENT_VM_RUNNING   , NULL } ,
    {"whenVmStopped"       , vm_with_name_stopped    , "s" , "string name" , EVENT_VM_STOPPED   , NULL } ,
    {"whenVmPaused"        , vm_with_name_paused     , "s" , "string name" , EVENT_VM_PAUSED    , NULL }
};

static unsigned int num_events = sizeof(event_data) / sizeof(event_data[0]);
static unsigned int num_conditions = sizeof(condition_data) / sizeof(condition_data[0]);


//Public data
struct ev_wrapper ** _vm_event_table;


//Initializes the module.
//The constructor attribute causes this function to run at load (dlopen()) time.
__attribute__((constructor)) static void init_module() {

    unsigned int i;

    //Allocate space for event tables.
    _vm_event_table = (struct ev_wrapper **)malloc(num_events * sizeof(struct ev_wrapper *));
    if (!(_vm_event_table)) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return;
    }

    //Add all events to the event list.
    for (i=0; i < num_events; ++i) {
        struct event_data_row entry = event_data[i];
        _vm_event_table[entry.index]  = add_event(entry.name, entry.is_stateless, entry.value_type, entry.reset_value);
    }

    //Add all condition_types to the condition_type list.
    for (i=0; i < num_conditions; ++i) {
        struct cond_table_row entry = condition_data[i];
        add_condition_type(entry.name, entry.func, entry.prototype, entry.pretty_prototype, _vm_event_table[entry.event_index], entry.on_instantiate);
    }

    //Set up a match and filter to get signals.
    add_dbus_filter("type='signal',interface='com.citrix.xenclient.xenmgr',member='vm_state_changed'", dbus_signal_handler, NULL, NULL);
}


//Cleans up after this module.
//The destructor attribute causes this to run at unload (dlclose()) time.
__attribute__((destructor)) static void uninit_module() {

    //Free event tables.
    free(_vm_event_table);

    //Remove DBus filter.
    remove_dbus_filter("type='signal',interface='com.citrix.xenclient.xenmgr',member='vm_state_changed'", dbus_signal_handler, NULL);
}


//Condition checkers
bool any_vm_creating(struct ev_wrapper * event, struct arg_node * args) {
    return true;
}

bool any_vm_stopping(struct ev_wrapper * event, struct arg_node * args) {
    return true;
}

bool any_vm_rebooting(struct ev_wrapper * event, struct arg_node * args) {
    return true;
}

bool any_vm_running(struct ev_wrapper * event, struct arg_node * args) {
    return true;
}

bool any_vm_stopped(struct ev_wrapper * event, struct arg_node * args) {
    return true;
}

bool any_vm_paused(struct ev_wrapper * event, struct arg_node * args) {
    return true;
}

bool vm_with_uuid_creating(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_uuid(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
	    free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_uuid_stopping(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_uuid(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
	    free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_uuid_rebooting(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_uuid(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
	    free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_uuid_running(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_uuid(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
	    free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_uuid_stopped(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_uuid(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
	    free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_uuid_paused(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_uuid(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
		free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_name_creating(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_name(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
		free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_name_stopping(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_name(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
		free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_name_rebooting(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_name(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
		free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_name_running(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_name(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
		free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_name_stopped(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_name(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
		free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}

bool vm_with_name_paused(struct ev_wrapper * event, struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    struct vm_identifier_table_row * vmid = new_vmid_search_result_by_name(node->arg.str);

    if (vmid && vmid->path && (0 == strcmp(event->value.str, vmid->path))) {
		free_vmid_search_result(vmid);
        return true;
    }
	free_vmid_search_result(vmid);
    return false;
}


//Multiple signals may be fired per actual vm state change. Consider tracking
//state internally and only triggering event on an edge.
void vm_state_changed(DBusMessage * dbus_message) {

    DBusError error;
    char * vm_uuid;
    void * obj_path; //We dont care about this
    char * vm_state;
    int acpi_state;
    struct ev_wrapper * e;
    struct vm_identifier_table_row * vmid;

    dbus_error_init(&error);
    if (!dbus_message_get_args(dbus_message, &error,
                               DBUS_TYPE_STRING, &vm_uuid,
                               DBUS_TYPE_OBJECT_PATH, &obj_path,
                               DBUS_TYPE_STRING, &vm_state,
                               DBUS_TYPE_INT32, &acpi_state,
                               DBUS_TYPE_INVALID)) {
        xcpmd_log(LOG_ERR, "dbus_message_get_args() failed: %s (%s).\n",
                  error.name, error.message);
        dbus_error_free(&error);
        return;
    }

    //For whatever reason the "creating" signal is fired multiple times, but
    //only once does it have the acpi_state of 5. At present, the acpi_state is
    //not meaningful, but this check prevents this signal from firing multiple
    //times per creation event. If this condition suddenly breaks, xenmgr's
    //behavior regarding this has probably changed.
    //The "stopping" signal also fires several times, but only once with acpi_state=0.
    if (0 == strcmp(vm_state, "creating") && acpi_state == 5) {
        e = _vm_event_table[EVENT_VM_CREATING];
    }
    else if (0 == strcmp(vm_state, "stopping") && acpi_state == 0) {
        e = _vm_event_table[EVENT_VM_STOPPING];
    }
    else if (0 == strcmp(vm_state, "rebooting")) {
        e = _vm_event_table[EVENT_VM_REBOOTING];
    }
    else if (0 == strcmp(vm_state, "running")) {
        e = _vm_event_table[EVENT_VM_RUNNING];
    }
    else if (0 == strcmp(vm_state, "stopped")) {
        e = _vm_event_table[EVENT_VM_STOPPED];
    }
    else if (0 == strcmp(vm_state, "paused")) {
        e = _vm_event_table[EVENT_VM_PAUSED];
    }
    else {
        return;
    }

    if (vm_uuid == NULL) {
        xcpmd_log(LOG_DEBUG, "dbus vm_changed signal's uuid is null!");
        return;
    }

    vmid = new_vmid_search_result_by_uuid(vm_uuid);
    if (vmid == NULL || vmid->path == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't find path of vm with uuid %s\n", vm_uuid);
    }
    else {
        e->value.str = vmid->path;
        handle_events(e);
    }
	free_vmid_search_result(vmid);
}


//This signal handler is called whenever a matched signal is received.
DBusHandlerResult dbus_signal_handler(DBusConnection * connection, DBusMessage * dbus_message, void * user_data) {

    //type = dbus_message_get_type(dbus_message);
    //path = dbus_message_get_path(dbus_message);
    //interface = dbus_message_get_interface(dbus_message);
    //member = dbus_message_get_member(dbus_message);
    //xcpmd_log(LOG_DEBUG, "DBus message: type=%i, interface=%s, path=%s, member=%s\n", type, interface, path, member);

    if (dbus_message_is_signal(dbus_message, "com.citrix.xenclient.xenmgr", "vm_state_changed")) {
	    vm_state_changed(dbus_message);

        //This return value prevents other signal handlers from acting on this signal.
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    //This return value allows other signal handlers to run after this one.
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

}
