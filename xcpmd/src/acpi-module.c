/*
 * acpi-module.c
 *
 * XCPMD module that monitors ACPI events.
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
#include "rules.h"
#include "acpi-module.h"
#include "battery.h"

/**
 * This module listens for ACPI events from acpid.
 */

//Function prototypes
bool bcl_up_pressed               (struct ev_wrapper * event, struct arg_node * args);
bool bcl_down_pressed             (struct ev_wrapper * event, struct arg_node * args);
bool pbtn_pressed                 (struct ev_wrapper * event, struct arg_node * args);
bool sbtn_pressed                 (struct ev_wrapper * event, struct arg_node * args);
bool susp_pressed                 (struct ev_wrapper * event, struct arg_node * args);
bool lid_closed                   (struct ev_wrapper * event, struct arg_node * args);
bool lid_open                     (struct ev_wrapper * event, struct arg_node * args);
bool on_ac                        (struct ev_wrapper * event, struct arg_node * args);
bool on_battery                   (struct ev_wrapper * event, struct arg_node * args);
bool tablet_mode                  (struct ev_wrapper * event, struct arg_node * args);
bool non_tablet_mode              (struct ev_wrapper * event, struct arg_node * args);
bool battery_greater_than         (struct ev_wrapper * event, struct arg_node * args);
bool battery_less_than            (struct ev_wrapper * event, struct arg_node * args);
bool battery_equal_to             (struct ev_wrapper * event, struct arg_node * args);
bool battery_present              (struct ev_wrapper * event, struct arg_node * args);
bool overall_battery_greater_than (struct ev_wrapper * event, struct arg_node * args);
bool overall_battery_less_than    (struct ev_wrapper * event, struct arg_node * args);
bool overall_battery_equal_to     (struct ev_wrapper * event, struct arg_node * args);


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
    {"event_pwr_btn"     , IS_STATELESS , ARG_BOOL , { .b = false       } , EVENT_PWR_BTN     } ,
    {"event_slp_btn"     , IS_STATELESS , ARG_BOOL , { .b = false       } , EVENT_SLP_BTN     } ,
    {"event_susp_btn"    , IS_STATELESS , ARG_BOOL , { .b = false       } , EVENT_SUSP_BTN    } ,
    {"event_bcl"         , IS_STATELESS , ARG_INT  , { .i = 0           } , EVENT_BCL         } ,
    {"event_lid"         , IS_STATEFUL  , ARG_INT  , { .i = LID_OPEN    } , EVENT_LID         } ,
    {"event_on_ac"       , IS_STATEFUL  , ARG_INT  , { .i = ON_AC       } , EVENT_ON_AC       } ,
    {"event_tablet_mode" , IS_STATEFUL  , ARG_INT  , { .i = NORMAL_MODE } , EVENT_TABLET_MODE } ,
    {"event_batt_status" , IS_STATELESS , ARG_INT  , { .i = 0           } , EVENT_BATT_STATUS } ,
    {"event_batt_info"   , IS_STATELESS , ARG_INT  , { .i = 0           } , EVENT_BATT_INFO   }

};


static struct cond_table_row condition_data[] = {
    {"onBacklightUpBtn"            , bcl_up_pressed               , "n"    , "void"                        , EVENT_BCL         , NULL } ,
    {"onBacklightDownBtn"          , bcl_down_pressed             , "n"    , "void"                        , EVENT_BCL         , NULL } ,
    {"onPowerBtn"                  , pbtn_pressed                 , "n"    , "void"                        , EVENT_PWR_BTN     , NULL } ,
    {"onSleepBtn"                  , sbtn_pressed                 , "n"    , "void"                        , EVENT_SLP_BTN     , NULL } ,
    {"onSuspendBtn"                , susp_pressed                 , "n"    , "void"                        , EVENT_SUSP_BTN    , NULL } ,
    {"whileLidClosed"              , lid_closed                   , "n"    , "void"                        , EVENT_LID         , NULL } ,
    {"whileLidOpen"                , lid_open                     , "n"    , "void"                        , EVENT_LID         , NULL } ,
    {"whileUsingAc"                , on_ac                        , "n"    , "void"                        , EVENT_ON_AC       , NULL } ,
    {"whileUsingBatt"              , on_battery                   , "n"    , "void"                        , EVENT_ON_AC       , NULL } ,
    {"whileInTabletMode"           , tablet_mode                  , "n"    , "void"                        , EVENT_TABLET_MODE , NULL } ,
    {"whileNotInTabletMode"        , non_tablet_mode              , "n"    , "void"                        , EVENT_TABLET_MODE , NULL } ,
    {"whileBattGreaterThan"        , battery_greater_than         , "i, i" , "int battNum, int percentage" , EVENT_BATT_STATUS , NULL } ,
    {"whileBattLessThan"           , battery_less_than            , "i, i" , "int battNum, int percentage" , EVENT_BATT_STATUS , NULL } ,
    {"whileBattEqualTo"            , battery_equal_to             , "i, i" , "int battNum, int percentage" , EVENT_BATT_STATUS , NULL } ,
    {"whileBattPresent"            , battery_present              , "i"    , "int battNum"                 , EVENT_BATT_INFO   , NULL } ,
    {"whileOverallBattGreaterThan" , overall_battery_greater_than , "i"    , "int percentage"              , EVENT_BATT_STATUS , NULL } ,
    {"whileOverallBattLessThan"    , overall_battery_less_than    , "i"    , "int percentage"              , EVENT_BATT_STATUS , NULL } ,
    {"whileOverallBattEqualTo"     , overall_battery_equal_to     , "i"    , "int percentage"              , EVENT_BATT_STATUS , NULL }
};

static unsigned int num_conditions = sizeof(condition_data) / sizeof(condition_data[0]);
static unsigned int num_events = sizeof(event_data) / sizeof(event_data[0]);


//Public data
struct ev_wrapper ** _acpi_event_table;


//Initializes the module.
//The constructor attribute causes this function to run at load (dlopen()) time.
__attribute__((constructor)) static void init_module() {

    unsigned int i;

    //Allocate space for event table.
    _acpi_event_table = (struct ev_wrapper **)malloc(num_events * sizeof(struct ev_wrapper *));

    if (_acpi_event_table == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return;
    }

    //Add all events to the event list.
    for (i=0; i < num_events; ++i) {
        struct event_data_row entry = event_data[i];
        _acpi_event_table[entry.index]  = add_event(entry.name, entry.is_stateless, entry.value_type, entry.reset_value);
    }

    //Add all condition_types to the condition_type list.
    for (i=0; i < num_conditions; ++i) {
        struct cond_table_row entry = condition_data[i];
        add_condition_type(entry.name, entry.func, entry.prototype, entry.pretty_prototype, _acpi_event_table[entry.event_index], entry.on_instantiate);
    }
}


//Cleans up after this module.
//The destructor attribute causes this to run at unload (dlclose()) time.
__attribute__((destructor)) static void uninit_module() {

    //Free event table.
    free(_acpi_event_table);
}


//Condition checkers
bool bcl_up_pressed(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == BCL_UP;
}


bool bcl_down_pressed(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == BCL_DOWN;
}



bool pbtn_pressed(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.b;
}


bool sbtn_pressed(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.b;
}


bool susp_pressed(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.b;
}


bool on_ac(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == ON_AC;
}


bool on_battery(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == ON_BATT;
}


bool lid_open(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == LID_OPEN;
}


bool lid_closed(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == LID_CLOSED;
}


bool tablet_mode(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == TABLET_MODE;
}


bool non_tablet_mode(struct ev_wrapper * event, struct arg_node * args) {

    return event->value.i == NORMAL_MODE;
}


bool battery_present(struct ev_wrapper * event, struct arg_node * args) {

    int check_battery_index = get_arg(args, 0)->arg.i;
    return battery_is_present(check_battery_index);
}


bool battery_greater_than(struct ev_wrapper * event, struct arg_node * args) {

    int percentage = get_arg(args, 0)->arg.i;
    return get_battery_percentage(event->value.i) > percentage;
}


bool battery_less_than(struct ev_wrapper * event, struct arg_node * args) {

    int percentage = get_arg(args, 0)->arg.i;
    return get_battery_percentage(event->value.i) < percentage;
}


bool battery_equal_to(struct ev_wrapper * event, struct arg_node * args) {

    int percentage = get_arg(args, 0)->arg.i;
    return get_battery_percentage(event->value.i) == percentage;
}


bool overall_battery_greater_than(struct ev_wrapper * event, struct arg_node * args) {

    int percentage = get_arg(args, 0)->arg.i;
    return get_overall_battery_percentage() > percentage;
}


bool overall_battery_less_than(struct ev_wrapper * event, struct arg_node * args) {

    int percentage = get_arg(args, 0)->arg.i;
    return get_overall_battery_percentage() < percentage;
}


bool overall_battery_equal_to(struct ev_wrapper * event, struct arg_node * args) {

    int percentage = get_arg(args, 0)->arg.i;
    return get_overall_battery_percentage() == percentage;
}
