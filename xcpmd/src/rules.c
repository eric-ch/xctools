/*
 * rules.c
 *
 * Provide basic framework for policy system.
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
#include <string.h>
#include <stdio.h>
#include "project.h"
#include "xcpmd.h"
#include "prototypes.h"
#include "rules.h"
#include "db-helper.h"


//Global variables
struct ev_wrapper events;
struct condition_type condition_types;
struct action_type action_types;
struct rule rules;
struct db_var db_vars;


//Functions
static char * long_prototype(char * short_prototype);
static void dec_variable_refs(struct rule * rule);
static void inc_variable_refs(struct rule * rule);


//Initializes all global lists.
//Constructor attribute causes this function to run at load time. Since this
//file's object is statically linked, this function runs before main().
__attribute__ ((constructor)) void init_rules() {

    INIT_LIST_HEAD(&events.list);
    INIT_LIST_HEAD(&condition_types.list);
    INIT_LIST_HEAD(&action_types.list);
    INIT_LIST_HEAD(&rules.list);
    INIT_LIST_HEAD(&db_vars.list);
}


//Free all memory that was dynamically allocated.
//Destructor attribute causes this function to run at unload time. Since this
//file's object is statically linked, this function runs after main().
__attribute__ ((destructor)) void uninit_rules() {

    struct list_head * posi, *i, *posj, *j;
    struct rule * tmp_rule;
    struct ev_wrapper * tmp_event;
    struct condition_node * tmp_condition_node;
    struct action_type * tmp_action_type;
    struct condition_type * tmp_condition_type;

    //Clean up all rules.
    list_for_each_safe(posi, i, &rules.list) {
        tmp_rule = list_entry(posi, struct rule, list);
        delete_rule(tmp_rule);
    }

    //Clean up all events.
    list_for_each_safe(posi, i, &events.list) {

        tmp_event = list_entry(posi, struct ev_wrapper, list);

        //Free all nodes in list event.listeners.
        list_for_each_safe(posj, j, &(tmp_event->listeners.list)) {
            tmp_condition_node = list_entry(posj, struct condition_node, list);
            list_del(posj);
            free(tmp_condition_node);
        }

        //And free the event itself.
        list_del(posi);
        free(tmp_event);
    }

    //Clean up all condition_types.
    list_for_each_safe(posi, i, &condition_types.list) {
        tmp_condition_type = list_entry(posi, struct condition_type, list);
        list_del(posi);
        free(tmp_condition_type);
    }

    //Clean up all action_types.
    list_for_each_safe(posi, i, &action_types.list) {
        tmp_action_type = list_entry(posi, struct action_type, list);
        list_del(posi);
        free(tmp_action_type);
    }

    //Clean up the db_var cache.
    delete_cached_vars();
}


//Allocates memory!
//Creates a new event and adds it to the shared list of events. Its default value is the reset value.
//Returns the new event.
struct ev_wrapper * add_event(char * event_name, bool is_stateless, enum arg_type value_type, union arg_u reset_value) {

    struct ev_wrapper * new_event = (struct ev_wrapper *)malloc(sizeof(struct ev_wrapper));
    if (new_event == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    new_event->name = event_name;
    new_event->is_stateless = is_stateless;
    new_event->value_type = value_type;
    new_event->reset_value = reset_value;
    new_event->value = reset_value;

    INIT_LIST_HEAD(&(new_event->listeners.list));

    list_add_tail(&(new_event->list), &(events.list));

    return new_event;
}


//Allocates memory!
//Creates a new condition_type and adds it to the shared list of condition_types.
//Returns the new condition type.
struct condition_type * add_condition_type(char * name, bool (* check)(struct ev_wrapper *, struct arg_node *), char * prototype, char * pretty_prototype, struct ev_wrapper * event, void (* on_instantiate)(struct condition *)) {

    struct condition_type * new_condition_type = (struct condition_type *)malloc(sizeof(struct condition_type));
    if (new_condition_type == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    new_condition_type->name = name;
    new_condition_type->check = check;
    new_condition_type->prototype = prototype;
    new_condition_type->pretty_prototype = pretty_prototype;
    new_condition_type->event = event;
    new_condition_type->on_instantiate = on_instantiate;

    list_add_tail(&(new_condition_type->list), &(condition_types.list));

    return new_condition_type;
}


//Allocates memory!
//Creates a new action_type and adds it to the shared list of action_types.
//Returns the new action type.
struct action_type * add_action_type(char * name, void (* action_func)(struct arg_node *), char * prototype, char * pretty_prototype) {

    struct action_type * new_action_type = (struct action_type *)malloc(sizeof(struct action_type));
    if (new_action_type == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    new_action_type->name = name;
    new_action_type->action = action_func;
    new_action_type->prototype = prototype;
    new_action_type->pretty_prototype = pretty_prototype;

    list_add_tail(&(new_action_type->list), &(action_types.list));

    return new_action_type;
}


//Allocates memory!
//Creates a new blank rule, but does not add it to the global linked list.
//Returns the new rule.
struct rule * new_rule(char * id) {

    struct rule * new_rule = (struct rule *)malloc(sizeof(struct rule));
    if (new_rule == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    new_rule->id = id;
    new_rule->is_active = false;
    new_rule->list.next = NULL;
    new_rule->list.prev = NULL;

    INIT_LIST_HEAD(&(new_rule->conditions.list));
    INIT_LIST_HEAD(&(new_rule->actions.list));
    INIT_LIST_HEAD(&(new_rule->undos.list));

    return new_rule;
}


//Allocates memory!
//Creates a new condition from a condition_type, then creates a corresponding
//condition_node and adds it to its event's list of listeners.
//Returns the new condition.
struct condition * new_condition(struct condition_type * type) {

    if (type == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't create new condition from null type\n");
        return NULL;
    }

    struct condition * new_condition = (struct condition *)malloc(sizeof(struct condition));
    struct condition_node * new_ref = (struct condition_node *)malloc(sizeof(struct condition_node));
    if (new_condition == NULL || new_ref == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    new_condition->type = type;
    new_condition->is_true = false;
    new_condition->is_inverted = false;

    INIT_LIST_HEAD(&(new_condition->args.list));

    new_ref->condition = new_condition;
    list_add_tail(&(new_ref->list), &(type->event->listeners.list));

    return new_condition;
}


//Allocates memory!
//Creates a new action from an action_type.
struct action * new_action(struct action_type * type) {

    if (type == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't create new action from null type\n");
        return NULL;
    }

    struct action * new_action = (struct action *)malloc(sizeof(struct action));
    if (new_action == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    new_action->type = type;

    INIT_LIST_HEAD(&(new_action->args.list));

    return new_action;
}


//Sets a condition's is_inverted member to true.
void invert_condition(struct condition * condition) {

    condition->is_inverted = true;
}


//Sets a condition's is_inverted member to false.
void uninvert_condition(struct condition * condition) {

    condition->is_inverted = false;
}


//Allocates memory!
//Add an argument to an existing condition.
void add_condition_arg(struct condition * condition, enum arg_type type, union arg_u arg) {

    if (condition == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add arg to null condition\n");
        return;
    }

    struct arg_node * new_arg = (struct arg_node *)malloc(sizeof(struct arg_node));
    if (new_arg == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return;
    }

    new_arg->type = type;
    new_arg->arg = arg;

    list_add_tail(&(new_arg->list), &(condition->args.list));
}


//Allocates memory!
//Adds an argument to an existing action.
void add_action_arg(struct action * action, enum arg_type type, union arg_u arg) {

    if (action == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add arg to null action\n");
        return;
    }

    struct arg_node * new_arg = (struct arg_node *)malloc(sizeof(struct arg_node));
    if (new_arg == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return;
    }

    new_arg->type = type;
    new_arg->arg = arg;

    list_add_tail(&(new_arg->list), &(action->args.list));
}


//Adds an existing condition to an existing rule's list of condition.
void add_condition_to_rule(struct rule * rule, struct condition * condition) {

    if (rule == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add condition to null rule\n");
        return;
    }
    if (condition == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add null condition to rule\n");
        return;
    }

    condition->rule = rule;
    list_add_tail(&(condition->list), &(rule->conditions.list));

    //Perform any initialization tasks that need doing.
    if (condition->type->on_instantiate) {
        condition->type->on_instantiate(condition);
    }
}


//Adds an existing action to an existing rule's list of actions.
void add_action_to_rule(struct rule * rule, struct action * action) {

    if (rule == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add action to null rule\n");
        return;
    }
    if (action == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add null action to rule\n");
        return;
    }

    list_add_tail(&(action->list), &(rule->actions.list));
}


//Adds an existing action to an existing rule's list of undo actions.
void add_undo_to_rule(struct rule * rule, struct action * action) {

    if (rule == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add undo action to null rule\n");
        return;
    }
    if (action == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add null undo action to rule\n");
        return;
    }

    list_add_tail(&(action->list), &(rule->undos.list));
}


//Adds an existing rule to the global list of rules. This really shouldn't be
//done before seeing if the rule passes validate_rule().
void add_rule(struct rule * rule) {

    if (rule == NULL) {
        xcpmd_log(LOG_DEBUG, "Couldn't add null rule to rule list\n");
        return;
    }

    rule->is_active = false;
    list_add_tail(&(rule->list), &(rules.list));
    inc_variable_refs(rule);
}


//Increments the refcount for all variables referenced by a rule.
//TODO: move to keeping references to rules instead of counts
static void inc_variable_refs(struct rule * rule) {

    struct condition * cond;
    struct action * act;
    struct arg_node * arg;
    struct db_var * var;

    //Increment condition variables.
    list_for_each_entry(cond, &rule->conditions.list, list) {
        list_for_each_entry(arg, &cond->args.list, list) {
            if (arg->type == ARG_VAR) {
                var = lookup_var(arg->arg.var_name);
                ++var->ref_count;
            }
        }
    }

    //Increment action variables.
    list_for_each_entry(act, &rule->actions.list, list) {
        list_for_each_entry(arg, &act->args.list, list) {
            if (arg->type == ARG_VAR) {
                var = lookup_var(arg->arg.var_name);
                ++var->ref_count;
            }
        }
    }

    //Increment undo action variables.
    list_for_each_entry(act, &rule->undos.list, list) {
        list_for_each_entry(arg, &act->args.list, list) {
            if (arg->type == ARG_VAR) {
                var = lookup_var(arg->arg.var_name);
                ++var->ref_count;
            }
        }
    }
}


//Decrements the refcount for all variables referenced by a rule.
static void dec_variable_refs(struct rule * rule) {

    struct condition * cond;
    struct action * act;
    struct arg_node * arg;
    struct db_var * var;

    //Decrement condition variables.
    list_for_each_entry(cond, &rule->conditions.list, list) {
        list_for_each_entry(arg, &cond->args.list, list) {
            if (arg->type == ARG_VAR) {
                var = lookup_var(arg->arg.var_name);
                --var->ref_count;
            }
        }
    }

    //Decrement action variables.
    list_for_each_entry(act, &rule->actions.list, list) {
        list_for_each_entry(arg, &act->args.list, list) {
            if (arg->type == ARG_VAR) {
                var = lookup_var(arg->arg.var_name);
                --var->ref_count;
            }
        }
    }

    //Decrement undo action variables.
    list_for_each_entry(act, &rule->undos.list, list) {
        list_for_each_entry(arg, &act->args.list, list) {
            if (arg->type == ARG_VAR) {
                var = lookup_var(arg->arg.var_name);
                --var->ref_count;
            }
        }
    }
}


//Deallocates all memory used for a rule, and if this rule is in the rule list,
//removes it. Reinitializes the rule list if it becomes empty.
void delete_rule(struct rule * rule) {

    struct list_head *posi, *i, *posj, *j;
    struct condition * tmp_condition;
    struct action * tmp_action;
    struct arg_node * tmp_arg;

    //If this rule has been added to the rule list, remove it and decrement all variable refcounts.
    if ((rule->list.prev != NULL) && (rule->list.next != NULL)) { //These will be null for a rule not in the list.
        list_del(&(rule->list));
        dec_variable_refs(rule);
    }

    //Free all nodes in list rule.conditions.
    list_for_each_safe(posi, i, &(rule->conditions.list)) {
        tmp_condition = list_entry(posi, struct condition, list);

        //Delete this condition from any list of listeners.
        delete_condition_from_listeners(tmp_condition);

        //Free the argument list.
        list_for_each_safe(posj, j, &(tmp_condition->args.list)) {
            tmp_arg = list_entry(posj, struct arg_node, list);

            //If the arg is a string, free the string.
            if (tmp_arg->type == ARG_STR)
                free(tmp_arg->arg.str);

            //If the arg is a variable, free the variable name.
            if (tmp_arg->type == ARG_VAR)
                free(tmp_arg->arg.var_name);

            list_del(posj);
            free(tmp_arg);
        }

        //And free the condition.
        list_del(posi);
        free(tmp_condition);
    }

    //Free all nodes in list rule.actions.
    list_for_each_safe(posi, i, &(rule->actions.list)) {
        tmp_action = list_entry(posi, struct action, list);

        //Free the argument list.
        list_for_each_safe(posj, j, &(tmp_action->args.list)) {
            tmp_arg = list_entry(posj, struct arg_node, list);

            //If the arg is a string, free the string.
            if (tmp_arg->type == ARG_STR)
                free(tmp_arg->arg.str);

            //If the arg is a variable, free the variable name.
            if (tmp_arg->type == ARG_VAR)
                free(tmp_arg->arg.var_name);

            list_del(posj);
            free(tmp_arg);
        }

        //And free the action.
        list_del(posi);
        free(tmp_action);
    }

    //Free all nodes in list rule.undos.
    list_for_each_safe(posi, i, &(rule->undos.list)) {
        tmp_action = list_entry(posi, struct action, list);

        //Free the argument list.
        list_for_each_safe(posj, j, &(tmp_action->args.list)) {
            tmp_arg = list_entry(posj, struct arg_node, list);

            //If the arg is a string, free the string.
            if (tmp_arg->type == ARG_STR)
                free(tmp_arg->arg.str);

            //If the arg is a variable, free the variable name.
            if (tmp_arg->type == ARG_VAR)
                free(tmp_arg->arg.var_name);

            list_del(posj);
            free(tmp_arg);
        }

        //And free the action.
        list_del(posi);
        free(tmp_action);
    }

    //Free the rule's ID string.
    free(rule->id);

    //Finally, free the rule itself.
    free(rule);

    //Reinitialize the list if this was the last rule.
    if (list_length(&rules.list) == 0)
        INIT_LIST_HEAD(&rules.list);
}


//Deletes all rules loaded. Does not modify the DB.
void delete_rules(void) {

    struct rule * rule, *tmp;

    list_for_each_entry_safe(rule, tmp, &rules.list, list) {
        delete_rule(rule);
    }
}


//Deletes a condition from an event's list of listeners.
void delete_condition_from_listeners(struct condition * condition) {

    struct ev_wrapper * event;
    struct condition_node *node, *tmp;

    event = condition->type->event;

    list_for_each_entry_safe(node, tmp, &event->listeners.list, list) {
        if (node->condition == condition) {
            list_del(&node->list);
            free(node);
            break;
        }
    }
}


//May allocate memory!
//Returns true if a list of arguments (of a condition or action) matches a prototype string.
//May free *err and replace with a malloc'd error string.
bool check_prototype(char * prototype, struct arg_node * args, char ** err) {

    char *to_check;
    char *ptr, *expected, *received;
    unsigned int prototype_length;
    enum arg_type type;
    bool ret;

    struct arg_node *arg, *resolved;

    to_check = NULL;
    list_for_each_entry(arg, &args->list, list) {
        if (arg->type == ARG_VAR) {
            resolved = resolve_var(arg->arg.var_name);
            if (resolved == NULL) {
                safe_str_append(err, "undefined variable: %s", arg->arg.var_name);
                return false;
            }
            type = resolved->type;
        }
        else {
            type = arg->type;
        }
        safe_str_append(&to_check, "%c ", (char)type);
    }

    if (to_check == NULL) {
        to_check = safe_sprintf("n");
    }
    else {
        //Chomp trailing space
        ptr = strchr(to_check, '\0');
        ptr -= sizeof(char);
        *ptr = '\0';
    }

    prototype_length = strlen(prototype);
    expected = long_prototype(prototype);
    received = long_prototype(to_check);

    if ((prototype_length < strlen(to_check)) || (prototype[0] == 'n' && to_check[0] != 'n')) {
        safe_str_append(err, "too many args supplied; expected \"%s\", received \"%s\"", expected, received);
        ret = false;
    }
    else if ((prototype_length > strlen(to_check)) || (prototype[0] != 'n' && to_check[0] == 'n')) {
        safe_str_append(err, "not enough args supplied; expected \"%s\", received \"%s\"", expected, received);
        ret = false;
    }
    else if (strcmp(prototype, to_check)) {
        safe_str_append(err, "invalid args supplied; expected \"%s\", received \"%s\"", expected, received);
        ret = false;
    }
    else {
        ret = true;
    }

    free(to_check);
    free(expected);
    free(received);

    return ret;
}


//Allocates memory!
//Returns the long form (e.g. "string, string, int") of a short prototype
//(e.g. "s s i").
static char * long_prototype(char * short_prototype) {

    char * ptr;
    char * long_prototype = NULL;

    if (short_prototype == NULL) {
        return clone_string("");
    }

    ptr = short_prototype;
    while (*ptr != '\0') {
        safe_str_append(&long_prototype, arg_type_to_string(*ptr));
        ptr += sizeof(char);
    }

    return long_prototype;
}


//Convert an arg_type to its string representation.
char * arg_type_to_string(char type) {
    switch(type) {
        case ARG_INT:
            return "int";
        case ARG_STR:
            return "string";
        case ARG_BOOL:
            return "bool";
        case ARG_NONE:
            return "void";
        case ARG_CHAR:
            return "char";
        case ARG_FLOAT:
            return "float";
        case ARG_VOIDPTR:
            return "void *";
        case ' ':
            return " ";
        case ARG_VAR:
            return "var";
        default:
            return "unknown_type";
    }
}


//May allocate memory!
//Returns true if a condition's arguments match the function prototype.
//May free *err and replace with a malloc'd error string.
bool check_condition(struct condition * condition, char ** err) {

    char * prototype = condition->type->prototype;
    struct arg_node * args = &(condition->args);
    bool pass;

    pass = check_prototype(prototype, args, err);

    if (!pass) {
        safe_str_append(err, " for condition %s", condition->type->name);
    }

    return pass;
}


//May allocate memory!
//Returns true if an action's arguments match the function prototype.
//May free *err and replace with a malloc'd error string.
bool check_action(struct action * action, char ** err) {

    char * prototype = action->type->prototype;
    struct arg_node * args = &(action->args);
    bool pass;

    pass = check_prototype(prototype, args, err);

    if (!pass) {
        safe_str_append(err, " for action %s", action->type->name);
    }

    return pass;
}


//May allocate memory!
//Ensure rule is valid:
// - No name collisions
// - At least one valid condition (args match prototype)
// - At least one valid action (args match prototype)
//Returns an error code as defined in rules.h.
//May free *err and replace with a malloc'd error string.
int validate_rule(struct rule * rule, char ** err) {

    struct rule * tmp_rule;
    struct condition * tmp_condition;
    struct action * tmp_action;

    if (rule->id == NULL || strlen(rule->id) == 0)
        return NO_NAME;

    list_for_each_entry(tmp_rule, &rules.list, list) {
        if (!strcmp(rule->id, tmp_rule->id)) {
            return NAME_COLLISION;
        }
    }

    if (list_empty(&rule->conditions.list)) {
        return NO_CONDITIONS;
    }

    if (list_empty(&rule->actions.list) && list_empty(&rule->undos.list)) {
        return NO_ACTIONS;
    }

    //Check all conditions for validity.
    list_for_each_entry(tmp_condition, &(rule->conditions.list), list) {
        if (!check_condition(tmp_condition, err)) {
            return BAD_PROTO;
        }
    }

    //Check all actions for validity.
    list_for_each_entry(tmp_action, &(rule->actions.list), list) {
        if (!check_action(tmp_action, err)) {
            return BAD_PROTO;
        }
    }

    //Check all undo actions for validity.
    list_for_each_entry(tmp_action, &(rule->undos.list), list) {
        if (!check_action(tmp_action, err)) {
            return BAD_PROTO;
        }
    }

    return RULE_VALID;
}


//Looks up a condition_type based on its namestring. Returns null on failure.
struct condition_type * lookup_condition_type(char * type) {

    struct condition_type * tmp_type;

    list_for_each_entry(tmp_type, &(condition_types.list), list) {
        if (strcmp(tmp_type->name, type) == 0)
            return tmp_type;
    }

    return NULL;
}


//Looks up an action_type based on its namestring. Returns null on failure.
struct action_type * lookup_action_type(char * type) {

    struct action_type * tmp_type;

    list_for_each_entry(tmp_type, &(action_types.list), list) {
        if (strcmp(tmp_type->name, type) == 0)
            return tmp_type;
    }

    return NULL;
}


//Looks up a rule based on its ID. Returns null on failure.
struct rule * lookup_rule(char * id) {

    struct rule * tmp_rule;

    list_for_each_entry(tmp_rule, &(rules.list), list) {
        if (strcmp(tmp_rule->id, id) == 0)
            return tmp_rule;
    }

    return NULL;
}


//Gets a reference to the most recently added rule.
struct rule * get_rule_tail() {

    if (list_empty(&rules.list)) {
        return NULL;
    }
    else {
        return list_entry(rules.list.prev, struct rule, list);
    }
}


//Allocates memory!
//Convenience function to create a new condition from a type string.
//Returns the new condition, or null on failure.
struct condition * new_condition_from_string(char * type_name) {

    struct condition_type * type = lookup_condition_type(type_name);
    struct condition * condition = new_condition(type);

    return condition;
}


//Allocates memory!
//Convenience function to create a new action from a type string.
//Returns the new action, or null on failure.
struct action * new_action_from_string(char * type_name) {

    struct action_type * type = lookup_action_type(type_name);
    struct action * action = new_action(type);

    return action;
}


//Returns the number of entries in a list.
int list_length(struct list_head * list_head) {

    int count = 0;
    struct list_head * pos;

    list_for_each(pos, list_head)
        ++count;

    return count;
}


//Returns true if all conditions in a rule are true.
bool evaluate_rule(struct rule * rule) {

    struct condition * condition;
    bool pass = true;

    list_for_each_entry(condition, &(rule->conditions.list), list) {
        pass &= condition->is_true;
    }

    return pass;
}


//Performs all actions in a rule.
void do_actions(struct rule * rule) {

    struct action * action;

    xcpmd_log(LOG_DEBUG, "Doing actions for rule %s.", rule_to_string(rule));
    list_for_each_entry(action, &(rule->actions.list), list) {
        action->type->action(&action->args);
    }
}


//Performs all undos in a rule, if they exist.
void do_undos(struct rule * rule) {

    struct action * undo;

    xcpmd_log(LOG_DEBUG, "Doing undos for rule %s.", rule_to_string(rule));
    if (!list_empty(&rule->undos.list)) {
        list_for_each_entry(undo, &(rule->undos.list), list) {
            undo->type->action(&undo->args);
        }
    }
}


//Prints all events in the global list "events".
void print_registered_events() {

    struct ev_wrapper * event;

    list_for_each_entry(event, &(events.list), list) {
        xcpmd_log(LOG_INFO, "Event: %s\n", event->name);
    }
    return;
}


//Allocates memory!
//Builds an array of strings describing all action types.
//Allocates memory for both the array and the strings within it.
//Places array pointer in argument and returns number of entries.
int get_registered_action_types(char *** array_ptr) {

    char ** string_arr;
    int num_entries, index;
    struct action_type * action;

    num_entries = list_length(&action_types.list);

    string_arr = (char **)malloc(num_entries * sizeof(char *));
    if (string_arr == NULL) {
        xcpmd_log(LOG_ERR, "Couldn't allocate memory\n");
        return 0;
    }

    *array_ptr = string_arr;

    index = 0;
    list_for_each_entry(action, &(action_types.list), list) {
        string_arr[index] = safe_sprintf("%s(%s)", action->name, action->pretty_prototype);
        ++index;
    }

    return num_entries;
}


//Allocates memory!
//Builds an array of strings describing all condition types.
//Allocates memory for both the array and the strings within it.
//Places array pointer in argument and returns number of entries.
int get_registered_condition_types(char *** array_ptr) {

    char ** string_arr;
    int num_entries, index;
    struct condition_type * condition;

    num_entries = list_length(&condition_types.list);

    string_arr = (char **)malloc(num_entries * sizeof(char *));
    if (string_arr == NULL) {
        xcpmd_log(LOG_ERR, "Couldn't allocate memory\n");
        return 0;
    }

    *array_ptr = string_arr;

    index = 0;
    list_for_each_entry(condition, &(condition_types.list), list) {
        string_arr[index] = safe_sprintf("%s(%s)", condition->name, condition->pretty_prototype);
        ++index;
    }

    return num_entries;
}


//Prints the name and prototype of all registered condition types.
void print_registered_condition_types() {

    struct condition_type * condition;

    list_for_each_entry(condition, &(condition_types.list), list) {
        xcpmd_log(LOG_INFO, "Condition type: %s(%s)\n", condition->name, condition->pretty_prototype);
    }
    return;
}


//Prints the name and prototype of all registered action types.
void print_registered_action_types() {

    struct action_type * action;

    list_for_each_entry(action, &(action_types.list), list) {
        xcpmd_log(LOG_INFO, "Action type: %s(%s)\n", action->name, action->pretty_prototype);
    }
    return;
}


//Allocates memory that must be freed.
char * arg_to_string(enum arg_type type, union arg_u value) {

    char * out;

    switch(type) {
        case ARG_STR:
            out = safe_sprintf("\"%s\"", value.str);
            break;
        case ARG_INT:
            out = safe_sprintf("%i", value.i);
            break;
        case ARG_BOOL:
            out = safe_sprintf("%s", value.b ? "t" : "f");
            break;
        case ARG_FLOAT:
            out = safe_sprintf("%f", value.f);
            break;
        case ARG_CHAR:
            out = safe_sprintf("'%c'", value.c);
            break;
        case ARG_VOIDPTR:
            out = safe_sprintf("0x%p", value.voidptr);
            break;
        case ARG_NONE:
            out = safe_sprintf("none");
            break;
        case ARG_VAR:
            out = safe_sprintf("$%s", value.var_name);
            break;
            //struct arg_node * var = resolve_var(value.var_name);
            //return arg_to_string(var->type, var->value);
        default:
            return NULL;
    }

    return out;
}


//Allocates memory!
//Converts a rule to a string form that can be used in a rules file.
char * rule_to_string(struct rule * rule) {
    struct condition * condition;
    struct action * action;
    struct arg_node * arg;
    char * out = NULL;
    char * tmp;

    out = safe_sprintf("%s | ", rule->id);
    list_for_each_entry(condition, &(rule->conditions.list), list) {
        if (condition->is_inverted) {
            safe_str_append(&out, "!");
        }
        safe_str_append(&out, "%s(", condition->type->name);
        list_for_each_entry(arg, &(condition->args.list), list) {
            tmp = arg_to_string(arg->type, arg->arg);
            safe_str_append(&out, "%s", tmp);
            free(tmp);
            if (arg->list.next != &condition->args.list) {
                safe_str_append(&out, " ");
            }
        }
        safe_str_append(&out, ") ");
    }

    safe_str_append(&out, "| ");
    list_for_each_entry(action, &(rule->actions.list), list) {
        safe_str_append(&out, "%s(", action->type->name);
        list_for_each_entry(arg, &(action->args.list), list) {
            tmp = arg_to_string(arg->type, arg->arg);
            safe_str_append(&out, "%s", tmp);
            free(tmp);
            if (arg->list.next != &action->args.list) {
                safe_str_append(&out, " ");
            }
        }
        safe_str_append(&out, ") ");
    }

    if (!list_empty(&rule->undos.list)) {
        safe_str_append(&out, "| ");
        list_for_each_entry(action, &(rule->undos.list), list) {
            safe_str_append(&out, "%s(", action->type->name);
            list_for_each_entry(arg, &(action->args.list), list) {
                tmp = arg_to_string(arg->type, arg->arg);
                safe_str_append(&out, "%s", tmp);
                free(tmp);
                if (arg->list.next != &action->args.list) {
                    safe_str_append(&out, " ");
                }
            }
            safe_str_append(&out, ") ");
        }
    }

    //Null out the trailing space
    if (out != NULL && strlen(out) >=1) {
        out[strlen(out) - 1] = '\0';
    }

    return out;
}


//Prints a description of a rule.
void print_rule(struct rule * rule) {

    struct condition * condition;
    struct action * action;
    struct arg_node * arg;
    char *line, *tmp;

    xcpmd_log(LOG_INFO, "Rule %s:\n", rule->id);

    xcpmd_log(LOG_INFO, "    Conditions:\n");
    list_for_each_entry(condition, &(rule->conditions.list), list) {
        line = safe_sprintf("        %s%s(", condition->is_inverted ? "!" : "", condition->type->name);
        list_for_each_entry(arg, &(condition->args.list), list) {
            tmp = arg_to_string(arg->type, arg->arg);
            safe_str_append(&line, "%s", tmp);
            free(tmp);
            if (arg->list.next != &condition->args.list) {
                safe_str_append(&line, ", ");
            }
        }
        safe_str_append(&line, ")\n");
        xcpmd_log(LOG_INFO, "%s", line);
        free(line);
        line = NULL;
    }

    xcpmd_log(LOG_INFO, "    Actions:\n");
    list_for_each_entry(action, &(rule->actions.list), list) {
        line = safe_sprintf("        %s(", action->type->name);
        list_for_each_entry(arg, &(action->args.list), list) {
            tmp = arg_to_string(arg->type, arg->arg);
            safe_str_append(&line, "%s", tmp);
            free(tmp);
            if (arg->list.next != &action->args.list) {
                safe_str_append(&line, ", ");
            }
        }
        safe_str_append(&line, ")\n");
        xcpmd_log(LOG_INFO, "%s", line);
        free(line);
        line = NULL;
    }

    xcpmd_log(LOG_INFO, "    Undos:\n");
    list_for_each_entry(action, &(rule->undos.list), list) {
        line = safe_sprintf("        %s(", action->type->name);
        list_for_each_entry(arg, &(action->args.list), list) {
            tmp = arg_to_string(arg->type, arg->arg);
            safe_str_append(&line, "%s", tmp);
            free(tmp);
            if (arg->list.next != &action->args.list) {
                safe_str_append(&line, ", ");
            }
        }
        safe_str_append(&line, ")\n");
        xcpmd_log(LOG_INFO, "%s", line);
        free(line);
    }
}


//Prints all rules in the global list of rules.
void print_rules(void) {

    struct rule * rule;

    list_for_each_entry(rule, &(rules.list), list) {
        print_rule(rule);
        xcpmd_log(LOG_INFO, "\n");
    }
}


//Gets an argument from an argument list by index, and resolves any variable
//references, if they exist. Assumes head is empty, making head->list->next
//have an index of 0.
struct arg_node * get_arg(struct arg_node * head, unsigned int index) {

    struct list_head * list_ptr;
    struct arg_node * ret;

    list_ptr = get_list_member_at_index(&head->list, index);
    ret = list_entry(list_ptr, struct arg_node, list);

    if (ret->type == ARG_VAR) {
        ret = resolve_var(ret->arg.var_name);
    }
    return ret;
}


//Gets the next argument in a linked list of arguments.
struct arg_node * next_arg(struct arg_node * arg) {

    struct arg_node * ret = list_entry(get_next_list_member(&arg->list), struct arg_node, list);

    if (ret->type == ARG_VAR) {
        ret = resolve_var(ret->arg.var_name);
    }
    return ret;
}


//Gets the list member at the specified index. Assumes head is empty, making
//head->next have an index of 0.
struct list_head * get_list_member_at_index(struct list_head * head, unsigned int index) {

    unsigned int i;
    struct list_head * ptr;

    ptr = head;

    for (i = 0; i <= index; ++i) {
        ptr = ptr->next;
    }

    return ptr;
}


//Gets the next linked list member.
struct list_head * get_next_list_member(struct list_head * head) {

    return head->next;
}


