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
 * @file msg.c
 * @author Tim Konick <konickt@ainfosec.com>
 * @date Thur Feb 28, 2019
 * @brief DBus request message handling.
 *
 * The code that filters messages passed off the policy rules lives here.
 */

#include "rpc-broker.h"


static inline char *get_db_vm_path(uint16_t domid)
{
#ifdef HAVE_XENSTORE
    size_t len;
    char path[256] = { 0 };
    char *uuid;
    struct xs_handle *xsh;

    xsh = xs_open(XS_OPEN_READONLY);

    if (!xsh)
       return NULL;

    snprintf(path, 255, "/local/domain/%d/vm", domid);

    uuid = (char *) xs_read(xsh, XBT_NULL, path, &len);
    if (uuid != NULL)
        DBUS_BROKER_EVENT("Find Domid Failed: %d", domid); 
    else
        DBUS_BROKER_EVENT("Found DOMID: %d", domid); 

    xs_close(xsh);

    return uuid;
#endif
    return NULL;
}

static int filter_if_bool(DBusConnection *conn, char *uuid,
                          char *bool_cond, bool bool_flag)
{
    char *arg, *attr_cond;
    int rc;

    rc = 0;
    arg = NULL;
    attr_cond = NULL;

    DBUS_REQ_ARG(arg, "%s/%s", uuid, bool_cond);
    attr_cond = db_query(conn, arg);
    free(arg);

    if (!attr_cond)
        return -1;

    if ((!strcmp("true", attr_cond) && bool_flag == false) ||
        (!strcmp("false", attr_cond) && bool_flag == true))
        rc = -1;

    free(attr_cond);

    return rc;
}

/*
static int filter_domtype(DBusConnection *conn, char *uuid,
                                                char *policy_domtype)
{
    int ret;
    char *arg, *dom_type;

    DBUS_REQ_ARG(arg, "%s/type", uuid);
    dom_type = db_query(conn, arg);
    free(arg);

    if (!dom_type)
        return -1;

    ret = 0;
    if (strcmp(policy_domtype, dom_type))
        ret = -1;

    free(dom_type);

    return ret;
}
*/

/*
 * Checks a rule for any given request, compares the policy-rule against
 * the dbus request being made.
 *
 * @param policy_rule One of the policy rules being compared against.
 * @param dmsg Structure object of the request being made.
 * @param domid Domain id from where the request came.
 *
 * @return 0 policy is to deny, 1 policy is to allow, -1 the rule did not match
 */
static int rule_matches_request(struct rule *policy_rule,
                                bool is_client,
                                struct dbus_message *dmsg,
                                uint16_t domid)
{
    //
    if (domid == 0)
        return 1;
    //
    DBusConnection *conn;
    char *uuid;
    int filter_policy;

    if (!policy_rule || !dmsg) {
        DBUS_BROKER_WARNING("Invalid filter request %s", "");
        return -1;
    }

    filter_policy = policy_rule->policy;
    conn = NULL;
    uuid = NULL;

    if (policy_rule->all)
        return filter_policy;

    if (!is_client && policy_rule->out)
        return filter_policy;
    else if (is_client && policy_rule->out)
        return -1;

    if ((policy_rule->stubdom && !is_stubdom(domid))                     ||
        (policy_rule->destination && strcmp(policy_rule->destination,
                                                 dmsg->destination))     ||
        (policy_rule->path && strcmp(policy_rule->path, dmsg->path))     ||
        (policy_rule->interface && strcmp(policy_rule->interface,
                                                 dmsg->interface))       ||
        (policy_rule->member && strcmp(policy_rule->member, dmsg->member))) {
        filter_policy = -1;
        goto policy_set;
    }

    if (!dbus_broker_policy->database)
        goto policy_set;

    if (policy_rule->if_bool || policy_rule->domtype) {
        conn = create_dbus_connection();
        uuid = get_db_vm_path(domid);
        if (uuid == NULL) {
            filter_policy = -1;
            goto policy_set;
        }

        if (policy_rule->if_bool &&
            filter_if_bool(conn, uuid, (char *) policy_rule->if_bool,
                                       policy_rule->if_bool_flag) < 0) {
            filter_policy = -1;
            goto policy_set;
        }
    }

policy_set:

    if (uuid)
        free(uuid);

    return filter_policy;
}

static struct domain_policy *get_domain_policy(char *uuid)
{
    int domains;
    int i;

    domains = dbus_broker_policy->domain_count;

    for (i=0; i < domains; i++) {
        if (!strcmp(dbus_broker_policy->domains[i].uuid_db_fmt, uuid))
            return &(dbus_broker_policy->domains[i]);
    }

    return NULL;
}

bool filter_property_request(struct dbus_message *dmsg, int domid)
{
    struct dbus_message property_req;

    property_req.destination = dmsg->destination;
    property_req.interface = ((char **) dmsg->args)[0];
    property_req.path = "/";

    if (strcmp(dmsg->member, "GetAll")) 
        property_req.member = ((char **) dmsg->args)[1];
    else
        property_req.member = "None";

    if (verbose_logging)
        DBUS_BROKER_EVENT("Filter Property: <%s> %s", property_req.destination, 
                                                      property_req.interface);
    return is_request_allowed(&property_req, true, domid);
}

/**
 * All requests are handled by this function whether they are raw requests
 * or Websocket requests.  For every policy rule listed either in the
 * /etc/rpc-broker.policy file or the domain-specific rules listed in the
 * xenclient database, each is passed to `filter` to determine whether or not
 * the message is dropped or passed through.
 *
 * @param dmsg The dbus request message fields.
 * @param domid The domain id of the where the request is being made.
 *
 * @return true to allow false to deny
 */
bool is_request_allowed(struct dbus_message *dmsg, bool is_client, int domid)
{
    bool allowed;
    int current_rule_policy;
    struct etc_policy domain_etc_policy;

    int i;
    char req_msg[1024] = { '\0' };
    char *uuid;

    if (!dmsg) {
        DBUS_BROKER_WARNING("Invalid args to broker-request %s", "");
        return false;
    }

    if (!dbus_broker_policy) {
        DBUS_BROKER_WARNING("No policy in place %s", "");
        return false;
    }

    /* deny by default */
    allowed = false;
    /* sets the current-rule-policy to default */
    current_rule_policy = 0;

    domain_etc_policy = dbus_broker_policy->domain_etc_policy;

    for (i=0; i < domain_etc_policy.count; i++) {
        current_rule_policy = rule_matches_request(&(domain_etc_policy.rules[i]),
                                                   is_client, dmsg, domid);
        /*
         *  1 = the rule matched the request and rule's policy is allow
         *  0 = the rule matched the request and rule's policy is deny
         * -1 = the rule did *not* match the request
         *
         *  The filter is set up as last match, with the default being "deny".
         *  Iterating through all the rules, if a rule matches a request, then
         *  update "allowed" to fit with the "current-rule-policy" (whether
         *  thats allow or deny).  If there is no match (-1) then "allowed"
         *  remains unchanged, remaining set as it was before the rule being
         *  checked.
         */
        if (current_rule_policy == -1)
            continue;

        allowed = current_rule_policy == 0 ? false : true;
    }

    if (!dbus_broker_policy->database || domid >= UUID_CACHE_LIMIT)
        goto filtering_done;

    if (domain_uuids[domid])
        uuid = domain_uuids[domid];
    else {
        uuid = get_uuid_from_domid(domid);
        domain_uuids[domid] = uuid;
    }

    if (!uuid)
        goto filtering_done;

    struct domain_policy *domain = get_domain_policy(uuid);

    if (!domain)
        goto filtering_done;

    for (i=0; i < domain->count; i++) {
        current_rule_policy = rule_matches_request(&(domain->rules[i]),
                                                   is_client, dmsg, domid);
        if (current_rule_policy == -1)
            continue;
        allowed = current_rule_policy == 0 ? false : true;
    }

    if (!strcmp("org.freedesktop.DBus.Properties", dmsg->interface)) 
        allowed = filter_property_request(dmsg, domid);

filtering_done:

    if (verbose_logging) {
        snprintf(req_msg, 1023, "Dom: %d [Dest: %s Path: %s Iface: %s Meth: %s]",
                          domid, dmsg->destination, dmsg->path,
                                 dmsg->interface, dmsg->member);

        if (allowed == true)
            DBUS_BROKER_EVENT("%s <%s>", req_msg, "Passed request");
        else
            DBUS_BROKER_WARNING("%s <%s>", req_msg, "Dropped request");
    }

    return allowed;
}

void debug_raw_buffer(char *buf, int rbytes)
{
    char tmp[DBUS_MSG_LEN] = { '\0' };

    int i;
    for (i=0; i < rbytes; i++) {
        if (isalnum(buf[i]))
            tmp[i] = buf[i];
        else
            tmp[i] = '-';
    }

    DBUS_BROKER_EVENT("5555: %s", tmp);
}

/*
 * This is an opaque exchange reading off from the receiving end of a raw-dbus
 * connection.  For rpc-broker sessions running "raw" mode, whenever a client
 * connects, another connection is opened on the bus.  Each of these sockets
 * are added to the event-loop.  Whenever a connection triggers the callback,
 * this function is invocated to receive the data being sent and then determine
 * (from the filter) if this message should be allowed or denied.
 *
 * @param rsock The socket ready to be read.
 * @param ssock The other end of the connection that possible gets sent to.
 * @param domid The domain id from where the data is being sent.
 * @param is_client A flag to show if this is client end being recv'd from.
 *
 * @return The total number of bytes exchanged, -1 for failure (block)
 */
int exchange(int rsock, int ssock, uint16_t domid, bool is_client)
{
    struct dbus_message dmsg;
    int total, rbytes, len;
    char buf[DBUS_MSG_LEN] = { 0 };

    total = 0;
    rbytes = 0;

    while ((rbytes = recv(rsock, buf, DBUS_MSG_LEN, 0)) > 0) {
        if (rbytes > DBUS_COMM_MIN) {

            len = dbus_message_demarshal_bytes_needed(buf, rbytes);

            if (len == rbytes) {
                if (convert_raw_dbus(&dmsg, buf, len) < 1)
                    return -1;
                if (is_request_allowed(&dmsg, is_client, domid) == false)
                    return -1;
            }
#ifdef DEBUG
        debug_raw_buffer(buf, rbytes);
#endif
        }

        total += rbytes;
        send(ssock, buf, rbytes, 0);
    }

    return total;
}

