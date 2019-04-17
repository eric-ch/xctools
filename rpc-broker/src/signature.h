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
 * @file signature.h
 * @author Tim Konick <konickt@ainfosec.com>
 * @date March 4, 2019
 * @brief signature handling declarations.
 *
 * All global variables and function declarations needed for parsing dbus
 * signatures. 
 */

#include <dbus/dbus.h>
#include <json.h>
#include <libxml/parser.h>


#define XML_SIGNATURE_MAX 16

static const xmlChar XML_NAME_PROPERTY[]      = "name";
static const xmlChar XML_DIRECTION_PROPERTY[] = "direction";

static const char XML_IN_FIELD[]           = "in";
static const char XML_TYPE_FIELD[]         = "type";


/* src/signature.c */
xmlNodePtr find_xml_property(const char *target, const xmlChar *property,
                             xmlNodePtr node);

int retrieve_xml_signature(const xmlChar *xml_dump, char *args,
                           const char *interface, const char *member);

void parse_dbus_dict(struct json_object *args, char *key, DBusMessageIter *iter);

void parse_signature(struct json_object *args, char *key, DBusMessageIter *iter);

