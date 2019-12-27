/*
 * platform.c
 *
 * XenClient platform management daemon platform quirks/specs setup
 *
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

#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>
#include <pci/header.h>
#include <pci/pci.h>
#include "project.h"
#include "xcpmd.h"
#include "battery.h"

/* Manufacturers */
#define MANUFACTURER_HP          "hewlett-packard"
#define MANUFACTURER_DELL        "dell"
#define MANUFACTURER_TOSHIBA     "toshiba"
#define MANUFACTURER_PANASONIC   "panasonic"
#define MANUFACTURER_LENOVO      "lenovo"
#define MANUFACTURER_FUJITSU     "fujitsu"
#define MANUFACTURER_FUJTSU      "fujtsu"
#define MANUFACTURER_APPLE       "Apple Inc."

/* PCI Values */
#define PCI_VENDOR_DEVICE_OFFSET 0x0
#define PCI_CLASS_REV_OFFSET     0x8
#define PCI_VIDEO_VGA_CLASS_ID   0x0300

/* PCI Intel Values */
#define INTEL_VENDOR_ID          0x8086
#define MONTEVINA_GMCH_ID        0x2a40
#define CALPELLA_GMCH_ID         0x0044
#define SANDYBRIDGE_GMCH_ID      0x0104

#define PCI_VENDOR_ID_WORD(v) ((uint16_t)(0xffff & (v)))
#define PCI_DEVICE_ID_WORD(v) ((uint16_t)(0xffff & (v >> 16)))
#define PCI_CLASS_ID_WORD(v) ((uint16_t)(0xffff & (v >> 16)))

uint32_t pm_quirks = PM_QUIRK_NONE;
uint32_t pm_specs = PM_SPEC_NONE;

/* Xenstore permissions */
#define XENSTORE_READ_ONLY      "r0"

static void *smbios_read_entry(char *id)
{
    char *buf;
    char path[PATH_MAX];
    int ret, off, len = 4096;

    sprintf(path, "/sys/class/dmi/id/%s", id);
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        xcpmd_log(LOG_ERR, "Could not open %s", path);
        return NULL;
    }

    buf = malloc(len);
    if (buf == NULL) {
        xcpmd_log(LOG_ERR, "%s malloc failed.", __func__);
        return NULL;
    }

    off = 0;
 read_more:
    ret = read(fd, buf + off, len - off);
    if (ret == -1) {
        xcpmd_log(LOG_ERR, "Error reading %s: %d %s", path, errno,
                  strerror(errno));
        return NULL;
    } else if (ret == 0) {
        /* End of file */
    } else if (ret < len - off) {
        off += ret;
        goto read_more;
    }

    close(fd);

    /* replace newline with NUL terminator */
    buf[off - 1] = '\0';

    return buf;
}

static void setup_software_bcl_and_input_quirks(void)
{
    char *manufacturer, *product, *bios_version;
    uint32_t pci_val;
    uint16_t pci_vendor_id, pci_gmch_id;

    manufacturer = smbios_read_entry("sys_vendor");
    if (manufacturer == NULL) {
        manufacturer = strdup("Unknown manufacturer");
    }
    product = smbios_read_entry("product_name");
    if (product == NULL) {
        product = strdup("Unknown product");
    }
    bios_version = smbios_read_entry("bios_version");
    if (bios_version == NULL) {
        bios_version = strdup("Unknown bios_version");
    }

    /* Read PCI information */
    pci_val = pci_host_read_dword(0, 0, 0, PCI_VENDOR_DEVICE_OFFSET);
    pci_vendor_id = PCI_VENDOR_ID_WORD(pci_val);
    pci_gmch_id = PCI_DEVICE_ID_WORD(pci_val);
    if ( pci_vendor_id != INTEL_VENDOR_ID )
    {
        xcpmd_log(LOG_WARNING, "%s unknown/unsupported chipset vendor ID: %x\n", __FUNCTION__, pci_vendor_id);
        goto out;
    }
    xcpmd_log(LOG_INFO, "Platform chipset Vendor ID: %4.4x GMCH ID: %4.4x\n", pci_vendor_id, pci_gmch_id);

    /* By default, turn on SW assistance for all systems then turn it off in cases where it is
     * known to be uneeded.
     */
    pm_quirks |= PM_QUIRK_SW_ASSIST_BCL|PM_QUIRK_SW_ASSIST_BCL_IGFX_PT;

    /* Filter out the manufacturers/products that need software assistance for BCL and other
     * platform functionality
     */
    if ( strnicmp(manufacturer, MANUFACTURER_HP, strlen(MANUFACTURER_HP)) == 0 )
    {
        /* HP platforms use keyboard input for hot-keys and guest software like QLB to drive BIOS
         * functionality for those keys via WMI. The flag allows the backend to field a few
         * of the hotkey presses when no guests are using them by processing the keyboard (via QLB).
         */
        pm_quirks |= PM_QUIRK_HP_HOTKEY_INPUT;

        /* Almost all the HPs used KB input for adjusting the brightness until an HDX VM is run with
         * the QLB/HotKey software. Once this VM is running, the guest software takes over and the BIOS
         * uses the IGD OpRegion to control brightness. The Sandybridge HP systems do not seem to be
         * doing what is excpected though. When it executes the WMI commands in SMM it does not return
         * the correct values to cause the ACPI brightness control code to use the IGD OpRegion so
         * the HotKey tools do not work. It does however generate the standard brightness SCI as a
         * workaround it can be handled with our support SW. TODO this needs to be addressed later.
         */
        if ( pci_gmch_id == SANDYBRIDGE_GMCH_ID )
            pm_quirks |= PM_QUIRK_SW_ASSIST_BCL_HP_SB;
        else
            pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL|PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
    }
    else if ( strnicmp(manufacturer, MANUFACTURER_DELL, strlen(MANUFACTURER_DELL)) == 0 )
    {
        /* MV and CP systems seem to use firmware BCL control but SB and IB do not */
        if ( (pci_gmch_id == MONTEVINA_GMCH_ID) || (pci_gmch_id == CALPELLA_GMCH_ID) )
            pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL|PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
    }
    else if ( strnicmp(manufacturer, MANUFACTURER_LENOVO, strlen(MANUFACTURER_LENOVO)) == 0 )
    {
        /* MV systems need software assistance
         * CP systems seem to use firmware
         * SB systems need software assistance including with Intel GPU passthrough
         */
        if ( pci_gmch_id == MONTEVINA_GMCH_ID )
            pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
        else if ( pci_gmch_id == CALPELLA_GMCH_ID )
            pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL|PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
    }
    else if ( (strnicmp(manufacturer, MANUFACTURER_FUJITSU, strlen(MANUFACTURER_FUJITSU)) == 0) ||
              (strnicmp(manufacturer, MANUFACTURER_FUJTSU, strlen(MANUFACTURER_FUJTSU)) == 0) )
    {
        /* CP systems like the E780 needs SW assistance and SB system E781 also needs it. Don't know about
         * any others so turn it on in all cases except for PVMs.
         */
        pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
    }
    else if ( strnicmp(manufacturer, MANUFACTURER_PANASONIC, strlen(MANUFACTURER_PANASONIC)) == 0 )
    {
        pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
    }
    else if ( strnicmp(manufacturer, MANUFACTURER_TOSHIBA, strlen(MANUFACTURER_TOSHIBA)) == 0 )
    {
        if ( (pci_gmch_id == MONTEVINA_GMCH_ID) || (pci_gmch_id == CALPELLA_GMCH_ID) )
            pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL|PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
        else
            pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
    }
    else if ( strnicmp(manufacturer, MANUFACTURER_APPLE, strlen(MANUFACTURER_APPLE)) == 0 )
    {
        pm_quirks &= ~(PM_QUIRK_SW_ASSIST_BCL_IGFX_PT);
    }

    xcpmd_log(LOG_INFO, "Platform manufacturer: %s product: %s BIOS version: %s\n", manufacturer, product, bios_version);

out:
    free(product);
    free(manufacturer);
    free(bios_version);
}

/* todo:
 * Eventually platform specs and quirk management will be moved to a central location (e.g. in
 * the config db and made available on dbus and xs). These values will will gobally available
 * for platform specific configurations. For now, the quirks are just being setup in xcpmd.
 */
void initialize_platform_info(void)
{
    uint32_t pci_val;
    uint16_t pci_vendor_id, pci_dev_id, pci_class_id;
    int batteries_present, battery_total, lid_status;

    if ( !pci_lib_init() )
    {
        xcpmd_log(LOG_ERR, "%s failed to initialize PCI utils library\n", __FUNCTION__);
        return;
    }

    /* Do setup stuffs */
    setup_software_bcl_and_input_quirks();

    /* Test for intel gpu - not dealing with multiple GPUs at the moment */
    pci_val = pci_host_read_dword(0, 2, 0, PCI_VENDOR_DEVICE_OFFSET);
    if ( pci_val != PCI_INVALID_VALUE )
    {
        pci_vendor_id = PCI_VENDOR_ID_WORD(pci_val);
        pci_dev_id = PCI_DEVICE_ID_WORD(pci_val);
        pci_class_id = PCI_CLASS_ID_WORD(pci_host_read_dword(0, 2, 0, PCI_CLASS_REV_OFFSET));
        if ( pci_class_id == PCI_VIDEO_VGA_CLASS_ID )
        {
            if ( pci_vendor_id == INTEL_VENDOR_ID )
                pm_specs |= PM_SPEC_INTEL_GPU;

            xcpmd_log(LOG_INFO, "Platform specs - GPU at 00:02.0 Vendor ID: %4.4x Device ID: %4.4x\n",
                      pci_vendor_id, pci_dev_id);
        }
        else
            xcpmd_log(LOG_INFO, "Platform specs - Device at 00:02.0 Class: %4.4x Vendor ID: %4.4x Device ID: %4.4x\n",
                      pci_class_id, pci_vendor_id, pci_dev_id);
    }
    else
        xcpmd_log(LOG_INFO, "Platform specs - no device at 00:02.0\n");


    /* Open the battery files if they are present and set the spec flag if
     * there are no batteries. Note that a laptop with no batteries connected
     * still reports all its battery slots but a desktop system will have an
     * empty battery list. At least some convertible tablets, however, will not
     * report the battery in the keyboard when disconnected.
     * (tested on HP Pro x2 612)
     */
    battery_total = get_num_batteries();
    xcpmd_log(LOG_DEBUG, "Found %d batteries.\n", battery_total);

    if (battery_total <= 0) {
        xcpmd_log(LOG_INFO, "No batteries or battery slots on platform.\n");
        pm_specs |= PM_SPEC_NO_BATTERIES;
    }
    else {
        batteries_present = get_num_batteries_present();
        xcpmd_log(LOG_INFO, "Battery information - total battery slots: %d  batteries present: %d\n", battery_total, batteries_present);
        //Xenstore init has moved to acpi-events.c
    }

    //Establishes whether this platform has a lid.
    lid_status = get_lid_status();

    if (lid_status == NO_LID) {
        xcpmd_log(LOG_INFO, "No lid on platform.\n");
        pm_specs |= PM_SPEC_NO_LID;
    }

    xcpmd_log(LOG_INFO, "Platform quirks: %8.8x specs: %8.8x\n", pm_quirks, pm_specs);

    pci_lib_cleanup();
}
