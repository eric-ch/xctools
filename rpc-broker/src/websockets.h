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
 * @file websockets.h
 * @author Tim Konick <konickt@ainfosec.com>
 * @date March 4, 2019
 * @brief Websocket declarations.
 *
 * Any global state variables and functions needed for Websocket handling.
 */

#include <libwebsockets.h>


#define WS_LOOP_TIMEOUT             100  /* length of time each service of the websocket */
                                         /* event-loop (millisecs) */
#define WS_RING_BUFFER_MEMBER_SIZE 8192
#define WS_RING_BUFFER_MEMBER_NUM    64

struct lws_ring *ring;


#define WS_USER_MEM_SIZE 8192  /* the amount memory that is allocated for user */
                               /* for each ws-callback */


struct json_response;

/* src/websockets.c */
char *prepare_json_reply(struct json_response *jrsp);

struct lws_context *create_ws_context(int port);

int ws_request_handler(struct lws *wsi, char *raw_req);

