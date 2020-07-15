/*
 * default-inputs-module.c
 *
 * XCPMD module that provides a dummy event.
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
#include "rules.h"
#include "default-inputs-module.h"

/**
 * This module provides a dummy event and condition, primarily for testing
 * purposes.
 */


//Function prototypes
static bool dummy_condition(struct ev_wrapper * event, struct arg_node * args);


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
static const struct event_data_row event_data[] = {
    {"dummy_event", IS_STATELESS, ARG_BOOL, { .b = false }, DUMMY_EVENT}
};

static const struct cond_table_row condition_table[] = {
    {"dummy_condition", dummy_condition, "n", "void", DUMMY_EVENT, NULL}
};

static const unsigned int num_events = sizeof(event_data) / sizeof(event_data[0]);
static const unsigned int condition_table_size = sizeof(condition_table) / sizeof(condition_table[0]);


//Public data
struct ev_wrapper ** default_event_table;


//Registers this module's events and condition types.
static void __attribute__((constructor)) init_module() {

    unsigned int i;

    default_event_table = (struct ev_wrapper **)malloc(num_events * sizeof(struct ev_wrapper *));

    for (i=0; i < num_events; ++i) {
        struct event_data_row entry = event_data[i];
        default_event_table[entry.index]  = add_event(entry.name, entry.is_stateless, entry.value_type, entry.reset_value);
    }

    for (i=0; i < condition_table_size; ++i) {
        struct cond_table_row entry = condition_table[i];
        add_condition_type(entry.name, entry.func, entry.prototype, entry.pretty_prototype, default_event_table[entry.event_index], entry.on_instantiate);
    }

}


//Cleans up after this module.
static void __attribute__((destructor)) uninit_module() {

    free(default_event_table);
}


//Condition checking functions
static bool dummy_condition(struct ev_wrapper * event, struct arg_node * args) {
    return event->value.b;
}
