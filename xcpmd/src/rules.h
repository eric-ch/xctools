/*
 * rules.h
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

#ifndef __RULES_H__
#define __RULES_H__

/**
 * The power management policy consists of a set of rules, and optionally variables as arguments to these rules.
 * A rule consists of an ID string, a set of conditions, a set of actions, and optionally a set of undo actions.
 * When all conditions are true, the rule becomes active, and the actions are executed in a set order.
 * When any condition becomes untrue, the rule becomes inactive, and its undo actions are executed in order.
 *
 * The set of condition types it is possible to trigger on are predefined as condition_type structs, which live in the
 * global list "condition_types". Condition_types are composed of a name, a "checker" function that returns a boolean,
 * a prototype string for the checker function, and a pointer to the event whose change triggers the evaluation of this
 * condition. The prototype is a simple list of space-separated characters; a map from characters to types is defined in
 * the arg_type enum. A C-style "pretty" prototype string is also included for self-documentation purposes.
 *
 * Conditions, which are structs instantiated from condition_types, belong to individual rules--each condition of each
 * rule is a unique object. A condition has a poiner to its rule, a pointer to the condition type it was instantiated from,
 * and a set of arguments to its checker function. A condition may also be inverted.
 *
 * Arguments are stored in arg_node structs that contain a union of possible types and an enum specifying the type.
 * Arguments of type string or var are assumed to contain malloc'd strings, which are free'd in undo functions.
 * Arguments of type var have a pointer to a db_var struct containing the cached DB value of that variable; more on
 * the variable cache is available in db-helper.c.
 *
 * Similarly to condition_types, there are also a set of action_types (stored in the global "action_types"). An
 * action_type has a name, a function returning void, a prototype for that function, and a pretty prototype for
 * documentation. Actions, which are unique for each rule, are instantiated from these action_types, and have a
 * pointer to their action_types and a set of arguments.
 *
 * The last main structure defined in this header is struct ev_wrapper, which is a thin wrapper around an input event, and
 * contains information necessary to the rule evaluation process. When an event of interest occurs, the corresponding
 * ev_wrapper's value field is modified, and handle_events() (which is defined in modules.c) is called with that ev_wrapper
 * as an argument. handle_events() checks all conditions that depend on that event (as defined in struct member listeners),
 * and if a condition has changed, evaluates the rule that contains that condition.
 *
 * At initialization, an ev_wrapper is given a name, a type, and a reset value (which is also used as an initial value), and
 * it is defined as stateful or stateless. There is some wiggle room with what events are inherently stateful or stateless,
 * but the most important difference is that stateless events have their values reset to their reset_values automatically
 * before exiting handle_events(). An example of a stateless event is a button push, where a keystroke event sets the
 * value to true for only an instant. Stateful events may be more appropriate for things like whether the lid is open or
 * closed, or the current battery percentage of the system.
 *
 * An ev_wrapper may have many conditions depending on it, but each condition may depend on only one ev_wrapper.
 *
 * A list of all ev_wrappers currently tracked is maintained in the global variable events. A module that registers
 * condition_types should also register the ev_wrappers that those condition_types depend on.
 *
 * Many of the data structures here rely on a linked list very close to that of the Linux kernel's. It is doubly-linked
 * and circular, and the heads of lists are empty.
 */

#include <stdbool.h>
#include "list.h"

#define IS_STATELESS true
#define IS_STATEFUL false

//Error codes output by validate_rule and consumed in parser.c.
#define RULE_CODE_NOT_SET   0x000
#define RULE_VALID          0x001
#define NO_NAME             0x002
#define NO_CONDITIONS       0x003
#define NO_ACTIONS          0x004
#define NAME_COLLISION      0x005
#define BAD_PROTO           0x006

//Data structures ahoy.


//Forward declarations
struct condition;
struct condition_node;


//A generic argument.
union arg_u {
    int i;
    bool b;
    char c;
    float f;
    char * str;
    void * voidptr;
    char * var_name;
};


//The type of a generic argument.
enum arg_type { ARG_INT='i', ARG_BOOL='b', ARG_CHAR='c', ARG_FLOAT='f', ARG_STR='s', ARG_VOIDPTR='p', ARG_NONE='n', ARG_VAR='v' };


//An argument and its type.
struct arg_node {
    struct list_head list;
    enum arg_type type;
    union arg_u arg;
};


//A linked list node pointing to an instantiated condition.
struct condition_node {
    struct list_head list;
    struct condition * condition;
};


//A thin wrapper around various types of input events. When an input event
//occurs, its corresponding event struct's value field is modified, and all
//conditions that are affected by this type of input event ("listeners")
//will be checked.
struct ev_wrapper {
    struct list_head list;
    char * name;
    bool is_stateless;
    struct condition_node listeners;
    enum arg_type value_type;
    union arg_u reset_value;
    union arg_u value;
};


//A definition of a type of condition. Each condition_type may depend
//on at most one input event. Its list member links it to the global
//list of condition_types.
struct condition_type {
    struct list_head list;
    char * name;
    bool (* check)(struct ev_wrapper *, struct arg_node *);
    char * prototype;
    char * pretty_prototype;
    struct ev_wrapper * event;
    void (* on_instantiate)(struct condition *); //Called whenever this condition_type is instantiated.
};


//An instantiation of a condition_type with added arguments. Each rule has a
//list of these. Its list member links it to a particular rule's condition list.
struct condition {
    struct list_head list;
    struct condition_type * type;
    struct rule * rule;
    bool is_true;
    bool is_inverted;
    struct arg_node args;
};


//A definition of a type of action. Its list member links it to the global list
//of action_types.
struct action_type {
    struct list_head list;
    char * name;
    void (* action)(struct arg_node *);
    char * prototype;
    char * pretty_prototype;
};


//An instantiation of an action_type with added arguments. Each rule has a list
//of these. Its list member links it to a particular rule's action list or undo
//action list.
struct action {
    struct list_head list;
    struct action_type * type;
    struct arg_node args;
};


//A container for rule data. Contains a unique ID string, a flag representing
//whether this rule is active or inactive, a set of conditions to evaluate, a
//set of actions to take if this rule moves from inactive to active, and a set
//of undo actions to take should this rule go from active to inactive.
struct rule {
    struct list_head list;
    char * id;
    struct condition conditions;
    struct action actions;
    struct action undos;
    bool is_active;
};


//A linked list node representing a variable from the DB.
struct db_var {
    struct list_head list;
    char * name;
    struct arg_node value;
    int ref_count;
};


//Shared data
extern struct condition_type condition_types;
extern struct action_type action_types;
extern struct rule rules;
extern struct ev_wrapper events;
extern struct db_var db_vars;


//Function prototypes
struct ev_wrapper * add_event(char * event_name, bool is_stateless, enum arg_type value_type, union arg_u reset_value);
struct condition_type * add_condition_type(char * name, bool (* check)(struct ev_wrapper *, struct arg_node *), char * prototype, char * pretty_prototype, struct ev_wrapper * event, void (*on_instantiate)(struct condition *));
struct action_type * add_action_type(char * name, void (* action_func)(struct arg_node *), char * prototype, char * pretty_prototype);

struct rule * new_rule(char * id);
struct condition * new_condition(struct condition_type * type);
struct action * new_action(struct action_type * action_type);

void invert_condition(struct condition * condition);
void uninvert_condition(struct condition * condition);

void add_condition_arg(struct condition * condition, enum arg_type type, union arg_u arg);
void add_action_arg(struct action * action, enum arg_type type, union arg_u arg);

void add_condition_to_rule(struct rule * rule, struct condition * condition);
void add_action_to_rule(struct rule * rule, struct action * action);
void add_undo_to_rule(struct rule * rule, struct action * action);

void add_rule(struct rule * rule);
void delete_rule(struct rule * rule);
void delete_rules(void);

void delete_condition_from_listeners(struct condition * condition);

bool check_prototype(char * prototype, struct arg_node * args, char ** err);
bool check_condition(struct condition * condition, char ** err);
bool check_action(struct action * action, char ** err);
int validate_rule(struct rule * rule, char ** err);

bool evaluate_rule(struct rule * rule);
void do_actions(struct rule * rule);
void do_undos(struct rule * rule);

struct ev_wrapper * lookup_event(int id);
struct condition_type * lookup_condition_type(char * type);
struct action_type * lookup_action_type(char * type);
struct rule * lookup_rule(char * id);
struct rule * get_rule_tail();

struct condition * new_condition_from_string(char *);
struct action * new_action_from_string(char *);

char * arg_to_string(enum arg_type type, union arg_u val);
char * arg_type_to_string(char type);

int get_registered_condition_types(char ** *array_ptr);
int get_registered_action_types(char ** *array_ptr);

void print_registered_condition_types();
void print_registered_action_types();
void print_registered_events();

void print_rule(struct rule * rule);
void print_rules(void);

char * rule_to_string(struct rule * rule);

struct arg_node * get_arg(struct arg_node * head, unsigned int index);
struct arg_node * next_arg(struct arg_node * arg);
struct list_head * get_list_member_at_index(struct list_head * head, unsigned int index);
struct list_head * get_next_list_member(struct list_head * head);
int list_length(struct list_head * list_head);

#endif
