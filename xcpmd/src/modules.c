/*
 * modules.c
 *
 * Provide high-level interface for loading modules and policy.
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

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include "project.h"
#include "xcpmd.h"
#include "modules.h"
#include "rules.h"
#include "parser.h"
#include "db-helper.h"

/**
 * This file deals with loading and unloading modules and policy.
 * It also provides handle_events(), the primary function called whenever an
 * event occurs. This triggers condition checks, and, if necessary, the
 * execution of actions or undo actions.
 *
 * This is the highest-level interface to the policy system.
 */


//Private data
static char * _module_list[] = {
    MODULE_PATH "acpi-module.so",
    MODULE_PATH "default-actions-module.so",
    MODULE_PATH "displayhandler-module.so",
    MODULE_PATH "idle-detect-module.so",
    MODULE_PATH "vm-actions-module.so",
    MODULE_PATH "vm-events-module.so",
};


//Loads all modules in _module_list.
int init_modules() {

    unsigned int num_modules = sizeof(_module_list) / sizeof(_module_list[0]);
    return load_modules(_module_list, num_modules);
}


//Unloads all modules in _module_list.
void uninit_modules() {

    unsigned int num_modules = sizeof(_module_list) / sizeof(_module_list[0]);
    unload_modules(_module_list, num_modules);
}


//Loads a module in a .so file by its filename.
//This implicitly calls its constructor function.
//NOTE: Constructors must be either static or uniquely named--since this
//application is linked with -rdynamic, all symbols linked in, even
//using dlopen, are in the namespace. This means that modules can shadow each
//other's functions if they have the same name. Be careful!
void * load_module(char * filename) {

    void * handle;
    char * err;

    handle = dlopen(filename, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        err = dlerror();
        if (err == NULL) {
            err = "(null)";
        }
        xcpmd_log(LOG_ERR, "Couldn't load module %s: %s\n", filename, err);
    }

    return handle;
}


//Unloads a module. This implicitly calls its destructor function.
//Once again, ensure that destructors are either static or uniquely named.
void unload_module(char * filename) {

    void * handle;

    handle = load_module(filename);
    if (handle == NULL) {
        return;
    }

    dlclose(handle);
}


//Loads a list of modules.
int load_modules(char ** module_list, unsigned int num_modules) {

    unsigned int i;

    for (i=0; i < num_modules; ++i) {
        if (load_module(module_list[i]) == NULL) {
            return -1;
        }
        else {
            xcpmd_log(LOG_DEBUG, "Loaded module %s", module_list[i]);
        }
    }

    return 0;
}


//Unloads a list of modules.
void unload_modules(char ** module_list, unsigned int num_modules) {

    unsigned int i;

    for (i=0; i < num_modules; ++i)
        unload_module(module_list[i]);
}


//On an event, checks conditions that depend on that event, evaluates any rules
//that depend on any changed conditions, and performs actions should any rule
//change from inactive to active or vice-versa.
void handle_events(struct ev_wrapper * event) {

    struct condition_node * node;
    struct condition * condition;
    struct rule ** checklist;
    struct rule ** alloc_check;
    unsigned int nodes_allocd = 8;
    unsigned int nodes_assigned = 0;
    unsigned int i;
    bool condition_is_true, condition_was_true;
    bool *rule_is_true, *rule_was_true;

    checklist = (struct rule **)malloc(nodes_allocd * sizeof(struct rule *));
    if (checklist == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return;
    }

    //Evaluate each condition that depends on this event.
    list_for_each_entry(node, &(event->listeners.list), list) {
        condition = node->condition;
        condition_was_true = condition->is_true;
        condition_is_true = condition->type->check(event, &condition->args);

        //If this condition has changed, add its rule to a rundown list.
        if (condition_was_true != condition_is_true) {

            //The rundown list is stored in a dynamic array that may need to be reallocated.
            if (nodes_assigned >= nodes_allocd) {
                alloc_check = (struct rule **)realloc(checklist, nodes_allocd * 2 * sizeof(struct rule *));
                if (alloc_check == NULL) {
                    xcpmd_log(LOG_ERR, "Failed to realloc memory\n");
                    free(checklist);
                    return;
                }
                checklist = alloc_check;
                nodes_allocd *= 2;
            }

            checklist[nodes_assigned] = condition->rule;
            ++nodes_assigned;
        }

        condition->is_true = condition_is_true;
    }

    //Evaluate each rule depending on those conditions.
    rule_is_true = (bool *)malloc(nodes_assigned * sizeof(bool));
    rule_was_true = (bool *)malloc(nodes_assigned * sizeof(bool));
    if (rule_is_true == NULL || rule_was_true == NULL) {
        xcpmd_log(LOG_ERR, "Failed to alloc memory");
        free(checklist);
        return;
    }

    for (i=0; i < nodes_assigned; ++i) {

        rule_was_true[i] = checklist[i]->is_active;
        rule_is_true[i] = evaluate_rule(checklist[i]);

        //Perform all undos first.
        if (rule_was_true[i] && !rule_is_true[i])
            do_undos(checklist[i]);
    }

    for (i=0; i < nodes_assigned; ++i) {

        //Then do actions.
        if (rule_is_true[i] && !rule_was_true[i])
            do_actions(checklist[i]);

        //Immediately reset the rule if the triggering event is stateless--this
        //prevents repeated events from being ignored.
        if (!event->is_stateless) {
            checklist[i]->is_active = rule_is_true[i];
        }
    }

    //Reset any events that are stateless, and the conditions that depend on them.
    if (event->is_stateless) {

        event->value = event->reset_value;

        list_for_each_entry(node, &(event->listeners.list), list) {
            condition = node->condition;
            condition->is_true = false;
        }
    }

    //Free any memory allocated.
    free(checklist);
    free(rule_is_true);
    free(rule_was_true);
}


//Gets a pointer to a particular module's event table by variable name.
//Expects table_module to be the filename of the module's .so file.
//It is essential that table names be unique to each module, or shadowing may
//occur.
struct ev_wrapper ** get_event_table(char * table_name, char * table_module) {

    void * handle;
    struct ev_wrapper *** table_ptr;
    struct ev_wrapper ** table;
    char * err;

    handle = dlopen(table_module, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        err = dlerror();
        if (err == NULL) {
            err = "(null)";
        }
        xcpmd_log(LOG_ERR, "Couldn't open module %s: %s\n", table_module, err);
        return NULL;
    }

    table_ptr = (struct ev_wrapper ***)dlsym(handle, table_name);
    if (table_ptr != NULL)
        table = *table_ptr;
    else {
        err = dlerror();
        if (err == NULL) {
            err = "(null)";
        }
        xcpmd_log(LOG_ERR, "Couldn't get event table %s from %s: %s\n", table_name, table_module, err);
        table = NULL;
    }
    xcpmd_log(LOG_DEBUG, "Got event table %s from %s.\n", table_name, table_module);

    return table;
}


//Update all conditions, then evaluate all rules.
void evaluate_policy(void) {

    struct ev_wrapper * event;
    struct condition_node * node;
    struct condition * condition;
    struct rule * rule;
    bool last_state;

    //For all stateful events, check all conditions.
    list_for_each_entry(event, &events.list, list) {
        if (event->is_stateless == FALSE) {
            list_for_each_entry(node, &(event->listeners.list), list) {
                condition = node->condition;

                last_state = condition->is_true;
                condition->is_true = condition->type->check(event, &condition->args);

                if (last_state != condition->is_true) {
                    xcpmd_log(LOG_DEBUG, "Condition %s became %s.", condition->type->name, condition->is_true ? "true" : "false");
                }
                else {
                    xcpmd_log(LOG_DEBUG, "Condition %s remains %s.", condition->type->name, condition->is_true ? "true" : "false");
                }
            }
        }
    }

    //Then evaluate all rules.
    //Perform all rules' undo actions first.
    list_for_each_entry(rule, &rules.list, list) {
        if (evaluate_rule(rule) == false) {
            if (rule->is_active) {
                do_undos(rule);
            }
            rule->is_active = false;
        }
    }

    //Then perform their actions.
    list_for_each_entry(rule, &rules.list, list) {
        if (evaluate_rule(rule) == true) {
            rule->is_active = true;
            do_actions(rule);
        }
    }
}


//Load policy from the DB.
int load_policy_from_db() {

    if (parse_config_from_db() != 0)
        return -1;

    return 0;
}


//Load policy from a file.
//This requires some cooperation from SELinux.
//See parser.c for information on policy file format.
int load_policy_from_file(char * filename) {

    if (parse_config_from_file(filename) == -1)
        return -1;

    write_db_rules();
    return 0;
}


//Checks if any rules or variables have yet been added.
bool policy_exists(void) {

    if (list_empty(&rules.list) && list_empty(&db_vars.list)) {
        return false;
    }
    else {
        return true;
    }
}
