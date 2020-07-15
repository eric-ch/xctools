/*
 * idle-detect-module.c
 *
 * XCPMD module that provides display power management actions.
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

#include "project.h"
#include "xcpmd.h"
#include "rpcgen/input_daemon_client.h"
#include "rules.h"
#include "modules.h"
#include "vm-utils.h"
#include "idle-detect-module.h"

#define DAR_TIMER_NAME "dar-shutdown"

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

struct timer {
    struct list_head list;
    char * name;
    int timeout;
    bool set;
    struct event set_event;
};


//Function prototypes
static DBusHandlerResult idle_timeout_handler(DBusConnection * connection, DBusMessage * dbus_message, void * user_data);
static void dar_idle_instantiate(struct condition * condition);
static bool dar_idle(struct ev_wrapper * event, struct arg_node * args);
static void set_timer(int fd, short event, void *opaque);
static struct timer * get_timer(char * name);
static struct timer * add_timer_to_list(char * name, int timeout);


//Private data
static struct event_data_row event_data[] = {
    {"event_on_idle", IS_STATELESS, ARG_STR, { .str = "" }, EVENT_ON_IDLE}
};

static struct cond_table_row condition_data[] = {
//    {"WhenIdleFor", on_idle, "i", "int timeout_seconds", EVENT_ON_IDLE, on_idle_instantiate}
    {"whenDarIdleTimeout", dar_idle, "i", "int timeout_seconds", EVENT_ON_IDLE, dar_idle_instantiate}
};

static unsigned int num_events = sizeof(event_data) / sizeof(event_data[0]);
static unsigned int num_conditions = sizeof(condition_data) / sizeof(condition_data[0]);

static struct timer timer_list;


//Public data
struct ev_wrapper ** _idle_event_table;


//Initializes the module.
//The constructor attribute causes this function to run at load (dlopen()) time.
__attribute__((constructor)) static void init_module() {

    unsigned i;

    //Allocate space for event tables.
    _idle_event_table = (struct ev_wrapper **)malloc(num_events * sizeof(struct ev_wrapper *));
    if (!(_idle_event_table)) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return;
    }

    //Add all events to the event list.
    for (i=0; i < num_events; ++i) {
        struct event_data_row entry = event_data[i];
        _idle_event_table[entry.index]  = add_event(entry.name, entry.is_stateless, entry.value_type, entry.reset_value);
    }

    //Add all condition_types to the condition_type list.
    for (i=0; i < num_conditions; ++i) {
        struct cond_table_row entry = condition_data[i];
        add_condition_type(entry.name, entry.func, entry.prototype, entry.pretty_prototype, _idle_event_table[entry.event_index], entry.on_instantiate);
    }

    //Initialize internal timer list
    INIT_LIST_HEAD(&timer_list.list);

    //Set up a match and filter to get signals.
    add_dbus_filter("type='signal',interface='com.citrix.xenclient.input',member='idle_timeout'", idle_timeout_handler, NULL, NULL);
}


//Cleans up after this module.
//The destructor attribute causes this to run at unload (dlclose()) time.
__attribute__((destructor)) static void uninit_module() {

    struct timer * t, *tmp;

    //Free event tables.
    free(_idle_event_table);

    //Remove DBus filter.
    remove_dbus_filter("type='signal',interface='com.citrix.xenclient.input',member='idle_timeout'", idle_timeout_handler, NULL);

    //Delete timer list.
    list_for_each_entry_safe(t, tmp, &timer_list.list, list) {
        list_del(&t->list);
        free(t->name);
        t->name = NULL;
        evtimer_del(&t->set_event);
        free(t);
    }
}


//Adds a timer to our internal list.
struct timer * add_timer_to_list(char * name, int timeout) {

    struct timer * new_timer;

    new_timer = (struct timer *)malloc(sizeof (struct timer));
    if (new_timer == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    new_timer->name = clone_string(name);
    if (new_timer->name == NULL) {
        free(new_timer);
        return NULL;
    }

    new_timer->set = false;
    new_timer->timeout = timeout;
    list_add(&new_timer->list, &timer_list.list);

    return new_timer;
}


//Checks if a timer is already in our internal list.
struct timer * get_timer(char * name) {

    struct timer * t;
    struct timer * found = NULL;

    list_for_each_entry(t, &timer_list.list, list) {
        if (strcmp(t->name, name) == 0) {
            found = t;
            break;
        }
    }

    return found;
}


//Instantiation callbacks
void dar_idle_instantiate(struct condition * condition) {

    int timeout;
    struct timer * timer;

    timeout = get_arg(&condition->args, 0)->arg.i;
    timer = get_timer(DAR_TIMER_NAME);

    //Does this timer exist yet?
    if (timer == NULL) {
        timer = add_timer_to_list(DAR_TIMER_NAME, timeout);
    }

    //Is this timer receiving a new timeout value?
    if (timer->timeout != timeout) {
        timer->set = false;
        timer->timeout = timeout;
    }

    //Does this timer still need to tell the input server?
    if (timer->set == false) {
        event_set(&timer->set_event, -1, EV_TIMEOUT | EV_PERSIST, set_timer, timer);
        set_timer(0, 0, timer);
    }
}


void set_timer(int fd, short event, void *opaque) {

    struct timeval tv;
    struct timer * timer = (struct timer *)opaque;

    xcpmd_log(LOG_DEBUG, "Sanity test.");

    if (timer == NULL || timer->name == NULL || get_timer(timer->name) == NULL) {
        xcpmd_log(LOG_DEBUG, "Timer event fired, but timer object seems to have disappeared?");
        return;
    }

    //Don't set a timeout of 0--at the time of writing, this causes the input server to constantly emit signals.
    if (timer->timeout == 0) {
        xcpmd_log(LOG_DEBUG, "Timer %s has a timeout of zero; not setting.\n", timer->name);
        timer->set = true;
        evtimer_del(&timer->set_event);
    }
    else if (com_citrix_xenclient_input_update_idle_timer_(xcdbus_conn, INPUT_SERVICE, INPUT_PATH, timer->name, timer->timeout * 60)) {
        xcpmd_log(LOG_DEBUG, "Updating timer %s with timeout %i.\n", timer->name, timer->timeout * 60);
        timer->set = true;
        evtimer_del(&timer->set_event);
    }
    else {
        xcpmd_log(LOG_DEBUG, "Updating timer %s failed; retrying...\n", timer->name);
        memset(&tv, 0, sizeof(tv));
        tv.tv_sec = 5;
        evtimer_add(&timer->set_event, &tv);
    }
}

//Condition checkers
bool dar_idle(struct ev_wrapper * event, struct arg_node * args) {

    return (strcmp(event->value.str, DAR_TIMER_NAME) == 0);
}


//This signal handler is called whenever a matched signal is received.
DBusHandlerResult idle_timeout_handler(DBusConnection * connection, DBusMessage * dbus_message, void * user_data) {

    //type = dbus_message_get_type(dbus_message);
    //path = dbus_message_get_path(dbus_message);
    //interface = dbus_message_get_interface(dbus_message);
    //member = dbus_message_get_member(dbus_message);
    //xcpmd_log(LOG_DEBUG, "DBus message: type=%i, interface=%s, path=%s, member=%s\n", type, interface, path, member);

    DBusError error;
    char * timer_name;
    struct timer * timer;
    struct ev_wrapper * e;
    DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    if (dbus_message_is_signal(dbus_message, "com.citrix.xenclient.input", "idle_timeout")) {

        dbus_error_init(&error);
        if (!dbus_message_get_args(dbus_message, &error, DBUS_TYPE_STRING, &timer_name, DBUS_TYPE_INVALID)) {
            xcpmd_log(LOG_ERR, "dbus_message_get_args() failed: %s (%s).\n", error.name, error.message);
        }
        dbus_error_free(&error);

        timer = get_timer(timer_name);
        if (timer != NULL) {
            if (timer->timeout > 0) {
                e = _idle_event_table[EVENT_ON_IDLE];
                e->value.str = timer_name;
                handle_events(e);
            }
            ret = DBUS_HANDLER_RESULT_HANDLED;
        }
    }

    return ret;
}
