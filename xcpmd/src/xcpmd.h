/*
 * xcpmd.h
 *
 * XenClient platform management daemon definitions
 *
 * Copyright (c) 2008 Kamala Narasimhan <kamala.narasimhan@citrix.com>
 * Copyright (c) 2011 Ross Philipson <ross.philipson@citrix.com>
 * Copyright (c) 2011 Citrix Systems, Inc.
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

#ifndef __XCPMD_H__
#define __XCPMD_H__

/* #define RUN_STANDALONE */
/* #define RUN_IN_SIMULATE_MODE */
/* #define XCPMD_DEBUG */
/* #define XCPMD_DEBUG_DETAILS */

#if __WORDSIZE == 64
#define UINT_FMT "%lx"
#else
#define UINT_FMT "%x"
#endif

#define XCPMD_SERVICE       "com.citrix.xenclient.xcpmd"
#define XCPMD_PATH          "/"
#define XENMGR_SERVICE      "com.citrix.xenclient.xenmgr"
#define XENMGR_VM_INTERFACE "com.citrix.xenclient.xenmgr.vm"
#define XENMGR_PATH         "/"
#define DB_SERVICE          "com.citrix.xenclient.db"
#define DB_PATH             "/"
#define INPUT_SERVICE       "com.citrix.xenclient.input"
#define INPUT_PATH          "/"

#define PCI_INVALID_VALUE 0xffffffff
#define EFI_LINE_SIZE     64

#define TIMEDOUT(t) ( (tv.tv_usec == 0) && (tv.tv_sec == 0) )

/* Input values defined here because RPC tool cannot generate enum values
 * from IDL yet.
 */
#define XCPMD_INPUT_SLEEP          1
#define XCPMD_INPUT_BRIGHTNESSUP   2
#define XCPMD_INPUT_BRIGHTNESSDOWN 3

/* Shared library handles opened up front */
extern xcdbus_conn_t *xcdbus_conn;

xcdbus_conn_t *xcpmd_get_xcdbus_conn(void);

enum BATTERY_INFO_TYPE {
    BIF,
    BST
};

enum BATTERY_PRESENT {
    NO = 0,
    YES = 1
};

enum BATTERY_UNIT {
    mW = 0,
    mA = 1
};

enum BATTERY_TECHNOLOGY {
    NON_RECHARGEABLE,
    RECHARGEABLE
};

enum BATTERY_LEVEL {
    NORMAL,
    WARNING,
    LOW,
    CRITICAL
};

enum BATTERY_STATE {
    BATT_STATE_UNKNOWN = 0,
    BATT_CHARGING = 1,
    BATT_DISCHARGING = 2,
    BATT_EMPTY = 3,
    BATT_FULL = 4,
    BATT_PENDING_CHARGE = 5,
    BATT_PENDING_DISCHARGE = 6
};

enum BCL_CMD {
    BCL_NONE,
    BCL_UP,
    BCL_DOWN,
    BCL_CYCLE
};

enum AC_ADAPTER {
    ON_AC,
    ON_BATT,
    AC_UNKNOWN,
    NO_AC
};

enum LID_STATE {
    LID_OPEN,
    LID_CLOSED,
    LID_UNKNOWN,
    NO_LID
};

enum TABLET_STATE {
    NORMAL_MODE,
    TABLET_MODE
};

struct battery_info {
    enum BATTERY_PRESENT    present;
    unsigned long charge_full_design; /* mA */
    unsigned long charge_full;        /* mA */
    unsigned long energy_full_design; /* mW */
    unsigned long energy_full;        /* mW */

    /* _BIF */
    enum BATTERY_UNIT       power_unit;
    unsigned long           design_capacity;
    unsigned long           last_full_capacity;
    enum BATTERY_TECHNOLOGY battery_technology;
    unsigned long           design_voltage;
    unsigned long           design_capacity_warning;
    unsigned long           design_capacity_low;
    unsigned long           capacity_granularity_1;
    unsigned long           capacity_granularity_2;
    char                    model_number[32];
    char                    serial_number[32];
    char                    battery_type[32];
    char                    oem_info[32];
};

struct battery_status {
    enum BATTERY_PRESENT    present;
    unsigned long current_now; /* mAh */
    unsigned long charge_now;  /* mA */
    unsigned long power_now;   /* mWh */
    unsigned long energy_now;  /* mW */

    /* _BST */
    unsigned long           state;
    unsigned long           present_rate;
    unsigned long           remaining_capacity;
    unsigned long           present_voltage;
};

#ifdef XCPMD_DEBUG_DETAILS
    void print_battery_info(struct battery_info *info);
    void print_battery_status(struct battery_status *status);
#else
    #define print_battery_info(x)
    #define print_battery_status(x)
#endif

#define BATTERY_DIR_PATH                    "/sys/class/power_supply"
#define AC_ADAPTER_DIR_PATH                 "/sys/class/power_supply/AC"
#define AC_ADAPTER_STATE_FILE_PATH          AC_ADAPTER_DIR_PATH"/online"
#define LID_DIR_PATH                        "/proc/acpi/button/lid/LID"
#define LID_DIR_PATH2                       "/proc/acpi/button/lid/LID0"
#define LID_STATE_FILE_PATH                 LID_DIR_PATH"/state"
#define LID_STATE_FILE_PATH2                LID_DIR_PATH2"/state"
#define ACPID_SOCKET_PATH                   "/var/run/acpid.socket"

#define XS_FORMAT_PATH_LEN                  128

//More generalized structure for multi-battery systems
#define XS_BATTERY_PATH                     "/pm/bat" //%i
#define XS_BIF_LEAF                         "bif"
#define XS_BST_LEAF                         "bst"
#define XS_BATTERY_PRESENT_LEAF             "present"
#define XS_BATTERY_LEVEL_LEAF               "current_level"

#define XS_BATTERY_EVENT_PATH               "/pm/events/bat" //%i
#define XS_BATTERY_INFO_EVENT_LEAF          "info_changed"
#define XS_BATTERY_STATUS_EVENT_LEAF        "status_changed"

#define XS_BATTERY_PRESENT                  "/pm/battery_present"
#define XS_BIF                              "/pm/bif"
#define XS_BST                              "/pm/bst"
#define XS_BIF1                             "/pm/bif1"
#define XS_BST1                             "/pm/bst1"
#define XS_CURRENT_BATTERY_LEVEL            "/pm/currentbatterylevel"
#define XS_AC_ADAPTER_STATE_PATH            "/pm/ac_adapter"
#define XS_LID_STATE_PATH                   "/pm/lid_state"
#define XS_CURRENT_TEMPERATURE              "/pm/current_temperature"
#define XS_CRITICAL_TEMPERATURE             "/pm/critical_temperature"
#define XS_BCL_CMD                          "/pm/bcl_cmd"

#define XS_PM_EVENTS_PATH                   "/pm/events"
#define XS_PM_EVENTS_TOKEN                  "xcpmd_token"

#define XS_BATTERY_STATUS_CHANGE_EVENT_PATH "/pm/events/batterystatuschanged"
#define XS_PWRBTN_EVENT_PATH                "/pm/events/powerbuttonpressed"
#define XS_SLPBTN_EVENT_PATH                "/pm/events/sleepbuttonpressed"
#define XS_SUSPBTN_EVENT_PATH               "/pm/events/suspendbuttonpressed"
#define XS_LID_EVENT_PATH                   "/pm/events/lidevent"
#define XS_BCL_EVENT_PATH                   "/pm/events/bclevent"
#define XS_XCMPD_SHUTDOWN_EVENT_PATH        "/pm/events/shutdownxcpmd"

#define BATTERY_WARNING_PERCENT   8
#define BATTERY_LOW_PERCENT       4
#define BATTERY_CRITICAL_PERCENT  2

#ifndef RUN_STANDALONE
# ifdef XCPMD_DEBUG
    #define xcpmd_log(priority, format, p...) syslog(priority, format, ##p)
# else
    #define xcpmd_log(priority, format, p...) priority == LOG_DEBUG ? : syslog(priority, format, ##p)
# endif
#else
# ifdef XCPMD_DEBUG
    #define xcpmd_log(priority, format, p...) printf(format, ##p)
# else
    #define xcpmd_log(priority, format, p...) priority == LOG_INFO ? : printf(format, ##p)
# endif
#endif

/* platform */
#define PM_QUIRK_NONE                       0x0000000
#define PM_QUIRK_SW_ASSIST_BCL              0x0000001 /* platform needs SW assistance with brightness adjustments */
#define PM_QUIRK_SW_ASSIST_BCL_IGFX_PT      0x0000002 /* platform needs SW assistance with brightness adjustments with Intel GPU pass-through */
#define PM_QUIRK_SW_ASSIST_BCL_HP_SB        0x0000004 /* set of HP SB platforms need SW assistance due to BIOS not switching to OpRegion use */
#define PM_QUIRK_HP_HOTKEY_INPUT            0x0010000 /* HP platforms generate keyboard input for hotkeys */

extern uint32_t pm_quirks;

#define PM_SPEC_NONE                        0x0000000
#define PM_SPEC_INTEL_GPU                   0x0000001 /* platform has an Intel GPU */
#define PM_SPEC_DIRECT_IO                   0x0000002 /* platform has direct IO hardware support like VTd */
#define PM_SPEC_NO_BATTERIES                0x0000004 /* platform has no batteries or battery slots (e.g. a Desktop system) */
#define PM_SPEC_NO_LID                      0x0000008 // platform has no lid switch

extern uint32_t pm_specs;

#define XCPMD_PID_FILE                      "/var/run/xcpmd.pid"

#define MODULE_PATH                         "/usr/lib/xcpmd/"
#define DB_PM_PATH                          "/power-management"
#define DB_VAR_MAP_PATH                     "/power-management/vars"
#define DB_RULE_PATH                        "/power-management/rules"

#define POLICY_FILE_PATH                    "/usr/share/xcpmd/default.rules"

#endif /* __XCPMD_H__ */
