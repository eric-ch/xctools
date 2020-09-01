/* qmp_helper.c
 *
 * QMP toolstack to stubdomain helper. This simple helper proxies a QMP
 * traffic between a local UNIX socket and a remote Argo QMP chardrv QEMU in
 * the stubdomain.
 *
 * Copyright (c) 2016 Assured Information Security, Ross Philipson <philipsonr@ainfosec.com>
 * Copyright (c) 2014 Citrix Systems, Inc.
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

#include "project.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <syslog.h>
#include <libargo.h>

/**
 * QMPH_LOG: information to always log (errors & important low-volume events)
 * @param fmt,... printf style arguments
 */
#define QMPH_LOG(fmt, ...)                                           \
do {                                                                 \
        syslog(LOG_NOTICE, "[%s:%d] (stubdom-%d) " fmt,              \
               __FUNCTION__, __LINE__, qhs.stubdom_id,               \
                 ##__VA_ARGS__);                                     \
    } while (0)

#define ARGO_TYPE 'W'
#define ARGOIOCSETRINGSIZE       _IOW (ARGO_TYPE,  1, uint32_t)

#define XEN_ARGO_MSG_SLOT_SIZE 0x10
#define XEN_ARGO_ROUNDUP(a) roundup((a), XEN_ARGO_MSG_SLOT_SIZE)

#define ARGO_QH_PORT 5100
#define ARGO_CHARDRV_PORT 15100
#define ARGO_CHARDRV_RING_SIZE \
  (XEN_ARGO_ROUNDUP((((4096)*4) - ARGO_RING_OVERHEAD)))

#define ARGO_CHARDRV_NAME  "[argo-chardrv]"

#define ARGO_MAGIC_CONNECT    "live"
#define ARGO_MAGIC_DISCONNECT "dead"

struct qmp_helper_state {
    int guest_id;
    int stubdom_id;
    int argo_fd;
    xen_argo_addr_t remote_addr;
    xen_argo_addr_t local_addr;
    int listen_fd;
    int unix_fd;
    bool connected;
    uint8_t msg_buf[ARGO_CHARDRV_RING_SIZE];
};

/* global helper state */
static struct qmp_helper_state qhs;

static int pending_exit = 0;

static void qmph_exit_cleanup(int exit_code)
{
    pending_exit = 1;

    /* close connection on the UNIX socket */
    close(qhs.unix_fd);
    qhs.unix_fd = -1;

    /* Done listening */
    close(qhs.listen_fd);

    /* close argo channel to stubdom */
    argo_close(qhs.argo_fd);
    qhs.argo_fd = -1;

    closelog();

    exit(exit_code);
}

static int argo_sendto_all(int argo_fd, const char *buf, const int size,
                           xen_argo_addr_t *addr)
{
    int sent = 0;
    int ret;

    while (sent < size) {
        ret = argo_sendto(argo_fd, buf + sent, size - sent, 0, addr);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }

            return -1;
        }

        sent += ret;
    }

    return ret;
}

static int qmp_magic_message(struct qmp_helper_state *pqhs,
                             const bool connect)
{

    int ret;
    const char *magic = connect ? ARGO_MAGIC_CONNECT : ARGO_MAGIC_DISCONNECT;
    const char *op = connect ? "connect" : "disconnect";
    const int sz = strlen(magic);

    if (pqhs->connected == connect) {
        QMPH_LOG("WARN: %s called when already %sed!\n", op, op);
        return 0;
    }

    ret = argo_sendto_all(pqhs->argo_fd, magic, sz, &pqhs->remote_addr);
    if (ret == sz) {
        pqhs->connected = connect;
    } else {
        QMPH_LOG("ERROR: %s failed\n", op);
    }

    return ret;
}

static int qmp_connect(struct qmp_helper_state *pqhs)
{
    return qmp_magic_message(pqhs, true);
}

static int qmp_disconnect(struct qmp_helper_state *pqhs)
{
    return qmp_magic_message(pqhs, false);
}

static int qmph_unix_to_argo(struct qmp_helper_state *pqhs)
{
    int ret, rcv;

    rcv = read(pqhs->unix_fd, pqhs->msg_buf, sizeof(pqhs->msg_buf));
    if (rcv < 0) {
        QMPH_LOG("ERROR read(unix_fd) failed (%s) - %d.\n",
                 strerror(errno), rcv);
        return rcv;
    }
    else if (rcv == 0) {
        QMPH_LOG("read(unix_fd) received EOF, telling qemu.\n");
        qmp_disconnect(pqhs);
        close(pqhs->unix_fd);
        pqhs->unix_fd = -1;
        return 0;
    }

    ret = argo_sendto(pqhs->argo_fd, pqhs->msg_buf,
                     rcv, 0, &pqhs->remote_addr);
    if (ret != rcv) {
        QMPH_LOG("ERROR argo_sendto() failed (%s) - %d %d.\n",
                 strerror(errno), ret, rcv);
        if (ret == -1) {
            QMPH_LOG("Closing unix socket");
            close(pqhs->unix_fd);
            pqhs->unix_fd = -1;
            pqhs->connected = false;
        }

        return -1;
    }

    return 0;
}

static int qmph_argo_to_unix(struct qmp_helper_state *pqhs)
{
    int ret, rcv;

    rcv = argo_recvfrom(pqhs->argo_fd, pqhs->msg_buf, sizeof(pqhs->msg_buf),
                       0, &pqhs->remote_addr);
    if (rcv < 0) {
        QMPH_LOG("ERROR argo_recvfrom() failed (%s) - %d.\n",
                 strerror(errno), rcv);
        return rcv;
    }

    if (pqhs->unix_fd == -1) {
        QMPH_LOG("Dropping %d argo bytes.\n", rcv);
        return 0;
    }

    ret = write(pqhs->unix_fd, pqhs->msg_buf, rcv);
    if (ret < 0) {
        QMPH_LOG("ERROR write(unix_fd) failed (%s) - %d.\n",
                 strerror(errno), ret);
        QMPH_LOG("closing unix_fd - maybe client disappeared");
        close(pqhs->unix_fd);
        pqhs->unix_fd = -1;
        return 0;
    }

    return 0;
}

static int qmph_init_argo_socket(struct qmp_helper_state *pqhs)
{
    uint32_t argo_ring_size = ARGO_CHARDRV_RING_SIZE;

    pqhs->argo_fd = argo_socket(SOCK_DGRAM);
    if (pqhs->argo_fd == -1) {
        QMPH_LOG("ERROR unable to create a argosocket");
        return -1;
    }

    pqhs->local_addr.aport = ARGO_QH_PORT;
    pqhs->local_addr.domain_id = 0;

    pqhs->remote_addr.aport = ARGO_CHARDRV_PORT;
    pqhs->remote_addr.domain_id = pqhs->stubdom_id;

    if (ioctl(pqhs->argo_fd, ARGOIOCSETRINGSIZE, &argo_ring_size) == -1) {
        QMPH_LOG("ERROR unable to send ioctl ARGOIOCSETRINGSIZE to argosocket");
        goto err;
    }

    if (argo_bind(pqhs->argo_fd, &pqhs->local_addr, pqhs->stubdom_id) == -1) {
        QMPH_LOG("ERROR unable to bind the argosocket");
        goto err;
    }

    return 0;

err:
    argo_close(pqhs->argo_fd);
    pqhs->argo_fd = -1;
    return -1;
}

static int qmph_accept_unix_socket(struct qmp_helper_state *pqhs)
{
    struct sockaddr_un un;
    socklen_t len = sizeof(un);
    int lfd, cfd;

    QMPH_LOG("Accepting connection on unix socket");

    lfd = pqhs->listen_fd;

    memset(&un, 0, sizeof(un));

    cfd = accept(lfd, (struct sockaddr*)&un, &len);
    if (cfd < 0) {
        QMPH_LOG("ERROR listen socket failed - err: %d", errno);
        goto err;
    }

    pqhs->unix_fd = cfd;

    return 0;
err:
    close(lfd);
    return -1;
}

static int qmph_init_unix_socket(struct qmp_helper_state *pqhs)
{
    struct sockaddr_un un;
    int lfd;

    /* By default the helper creates a Unix socket as if QEMU were called with:
     * -qmp unix:/var/run/xen/qmp-libxl-<domid>,server,nowait
     */

    pqhs->unix_fd = -1;

    /* First step, start the listener then wait for a connection */
    lfd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) {
        QMPH_LOG("ERROR create socket failed - err: %d", errno);
        return -1;
    }

    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    snprintf(un.sun_path, sizeof(un.sun_path),
             "/var/run/xen/qmp-libxl-%d", pqhs->guest_id);

    unlink(un.sun_path);

    if (bind(lfd, (struct sockaddr*)&un, sizeof(un)) < 0) {
        QMPH_LOG("ERROR bind socket failed - err: %d", errno);
        goto err;
    }

    if (listen(lfd, 1) < 0) {
        QMPH_LOG("ERROR listen socket failed - err: %d", errno);
        goto err;
    }

    pqhs->listen_fd = lfd;

    return 0;

err:
    close(lfd);
    return -1;
}

static void qmph_signal_handler(int sig)
{
    QMPH_LOG("handle signal %d", sig);
    qmph_exit_cleanup(0);
}

int main(int argc, char *argv[])
{
    fd_set rfds;
    int nfds, ret;

    openlog(NULL, LOG_NDELAY, LOG_DAEMON);

    QMPH_LOG("starting %s\n", argv[0]);

    memset(&qhs, 0, sizeof(qhs));

    if (argc != 3) {
        QMPH_LOG("usage: %s <guest_id> <stubdom_id>", argv[0]);
        return -1;
    }

    qhs.guest_id = atoi(argv[1]);

    if (qhs.guest_id < 0) {
        QMPH_LOG("ERROR bad guest id (%d)", qhs.guest_id);
        return -1;
    }

    qhs.stubdom_id = atoi(argv[2]);

    if (qhs.stubdom_id < 0) {
        QMPH_LOG("ERROR bad stubdom id (%d)", qhs.stubdom_id);
        return -1;
    }

    signal(SIGINT, qmph_signal_handler);

    ret = qmph_init_argo_socket(&qhs);
    if (ret) {
        QMPH_LOG("ERROR failed to init argo socket - ret: %d\n", ret);
        return -1;
    }

    QMPH_LOG("argo ready, wait for a connection...");

    ret = qmph_init_unix_socket(&qhs);
    if (ret) {
        QMPH_LOG("ERROR failed to init unix socket - ret: %d\n", ret);
        qmph_exit_cleanup(ret);
    }

    while (!pending_exit) {

        nfds = -1;
        FD_ZERO(&rfds);
        if (qhs.argo_fd >= 0) {
            FD_SET(qhs.argo_fd, &rfds);
            nfds = qhs.argo_fd > nfds ? qhs.argo_fd : nfds;
        }
        if (qhs.unix_fd >= 0) {
            FD_SET(qhs.unix_fd, &rfds);
            nfds = qhs.unix_fd > nfds ? qhs.unix_fd : nfds;
        }
        /* Accept new connections when unix_fd is closed (not connected). */
        if (qhs.unix_fd == -1 && qhs.listen_fd >= 0) {
            FD_SET(qhs.listen_fd, &rfds);
            nfds = qhs.listen_fd > nfds ? qhs.listen_fd : nfds;
        }
        nfds += 1;

        if (select(nfds, &rfds, NULL, NULL, NULL) == -1) {
            ret = errno;
            QMPH_LOG("ERROR failure during select - err: %d\n", ret);
            qmph_exit_cleanup(ret);
        }

        if (FD_ISSET(qhs.listen_fd, &rfds)) {
            ret = qmph_accept_unix_socket(&qhs);
            if (ret) {
                QMPH_LOG("ERROR failed to accept unix socket - ret: %d\n", ret);
                qmph_exit_cleanup(ret);
            }
            QMPH_LOG("Accepted the connection fd: %d, telling qemu.", qhs.unix_fd);
            ret = qmp_connect(&qhs);
            if (ret == -1) {
                QMPH_LOG("ERROR qmp_connect refused: closing unix socket\n");
                /* close connection on the UNIX socket */
                close(qhs.unix_fd);
                qhs.unix_fd = -1;
            }
        }

        if (FD_ISSET(qhs.unix_fd, &rfds)) {
            if (qmph_unix_to_argo(&qhs))
                break; /* abject misery */
        }

        if (FD_ISSET(qhs.argo_fd, &rfds)) {
            if (qmph_argo_to_unix(&qhs))
                break; /* total death */
        }
    }

    QMPH_LOG("exiting...\n");
    qmph_exit_cleanup(0);
    return 0;
}
