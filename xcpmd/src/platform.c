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

/* Dell 5X20 series */
#define DELL_E5220               "E5220"
#define DELL_E5420               "E5420"
#define DELL_E5520               "E5520"
#define TOSHIBA_TECRA            "TECRA"

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

#define SCAN_ROM_BIOS_BASE 0xF0000
#define SCAN_ROM_BIOS_SIZE 0x10000

uint32_t pm_quirks = PM_QUIRK_NONE;
uint32_t pm_specs = PM_SPEC_NONE;

/* SMBIOS Lengths */
#define SMBIOS_SM_LENGTH       0x20
#define SMBIOS_DMI_LENGTH      0x0F
#define SMBIOS_HEADER_LENGTH   0x04

/* SMBIOS Offsets */
#define SMBIOS_EPS_STRING      0x00 /* 4 BYTES "_SM_" anchor string */
#define SMBIOS_EPS_CHECKSUM    0x04 /* BYTE CS sums to zero when added to bytes in EPS */
#define SMBIOS_EPS_LENGTH      0x05 /* BYTE Length of the Entry Point Structure */
#define SMBIOS_MAJOR_VERSION   0x06 /* BYTE */
#define SMBIOS_MINOR_VERSION   0x07 /* BYTE */
#define SMBIOS_MAX_STRUCT_SIZE 0x08 /* WORD Size of the largest SMBIOS structure */
#define SMBIOS_REVISION        0x0A /* BYTE */
#define SMBIOS_FORMATTED_AREA  0x0B /* 5 BYTES, see spec for revision */
#define SMBIOS_IEPS_STRING     0x10 /* 5 BYTES "_DMI_" intermediate anchor string */
#define SMBIOS_IEPS_CHECKSUM   0x15 /* BYTE CS sums to zero when added to bytes in IEPS */
#define SMBIOS_TABLE_LENGTH    0x16 /* WORD Total length of SMBIOS Structure Table */
#define SMBIOS_TABLE_ADDRESS   0x18 /* DWORD The 32-bit physical starting address of the read-only SMBIOS Structures */
#define SMBIOS_STRUCT_COUNT    0x1C /* WORD Total number of structures present in the SMBIOS Structure Table */
#define SMBIOS_BCD_REVISION    0x1E /* BYTE */

#define SMBIOS_STRUCT_TYPE     0x00 /* BYTE Specifies the type of structure */
#define SMBIOS_STRUCT_LENGTH   0x01 /* BYTE Specifies the length of the formatted area of the structure */
#define SMBIOS_STRUCT_HANDLE   0x02 /* WORD Specifies 16-bit number in the range 0 to 0FFFEh */

/* SMBIOS Types */
#define SMBIOS_TYPE_BIOS_INF0    0
#define SMBIOS_TYPE_SYSTEM_INFO  1
#define SMBIOS_TYPE_BASE_BOARD   2
#define SMBIOS_TYPE_ENCLOSURE    3
#define SMBIOS_TYPE_INACTIVE     126
#define SMBIOS_TYPE_EOT          127
#define SMBIOS_TYPE_VENDOR_MIN   128
#define SMBIOS_TYPE_VENDOR_MAX   255

/* Xenstore permissions */
#define XENSTORE_READ_ONLY      "r0"

struct smbios_locator {
    size_t phys_addr;
    uint16_t length;
    uint16_t count;
    uint8_t *addr;
};

struct smbios_header {
    uint8_t type;
    uint8_t length;
    uint16_t handle;
} __attribute__ ((packed));

struct smbios_bios_info {
    struct smbios_header header;
    uint8_t vendor_str;
    uint8_t version_str;
    uint16_t starting_address_segment;
    uint8_t release_date_str;
    uint8_t rom_size;
    uint8_t characteristics[8];
    uint8_t characteristics_extension_bytes[2];
    uint8_t major_release;
    uint8_t minor_release;
    uint8_t embedded_controller_major;
    uint8_t embedded_controller_minor;
} __attribute__ ((packed));

struct smbios_system_info {
    struct smbios_header header;
    uint8_t manufacturer_str;
    uint8_t product_name_str;
    uint8_t version_str;
    uint8_t serial_number_str;
    uint8_t uuid[16];
    uint8_t wake_up_type;
    uint8_t sku_str;
    uint8_t family_str;
} __attribute__ ((packed));

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

static int smbios_entry_point(struct smbios_locator *locator, uint8_t *entry_point, int is_eps)
{
    uint8_t cs;
    uint32_t count;

    if (is_eps)
    {
        /* checksum sanity check on _SM_ entry point */
        for ( cs = 0, count = 0; count < entry_point[SMBIOS_EPS_LENGTH]; count++ )
            cs += entry_point[count];
        if ( cs != 0 )
        {
            xcpmd_log(LOG_WARNING, "Invalid _SM_ checksum\n");
            return -1;
        }
        /* nothing else really interesting in the EPS, move to the IEPS */
        entry_point += SMBIOS_IEPS_STRING;
        if ( memcmp(entry_point, "_DMI_", 5) != 0 )
        {
            xcpmd_log(LOG_WARNING, "Entry point structure missing _DMI_ anchor\n");
            return -1;
        }
    }

    /* entry point is IEPS, do checksum of this portion */
    for ( cs = 0, count = 0; count < SMBIOS_DMI_LENGTH; count++ )
        cs += entry_point[count];
    if ( cs != 0 )
    {
        xcpmd_log(LOG_WARNING, "Invalid _DMI_ checksum\n");
        return -1;
    }

    locator->phys_addr = (*(uint32_t*)(entry_point + SMBIOS_TABLE_ADDRESS - SMBIOS_IEPS_STRING));
    locator->length = (*(uint16_t*)(entry_point + SMBIOS_TABLE_LENGTH - SMBIOS_IEPS_STRING));
    locator->count = (*(uint16_t*)(entry_point + SMBIOS_STRUCT_COUNT - SMBIOS_IEPS_STRING));

    /* sanity */
    if ( (locator->length < 4) || (locator->count == 0) ) {
        xcpmd_log(LOG_WARNING, "Entry point structure reporting invalid length or count\n");
        return -1;
    }

    locator->addr = map_phys_mem(locator->phys_addr, locator->length);
    if ( locator->addr == NULL )
    {
        xcpmd_log(LOG_ERR, "Failed to map SMBIOS structures at phys="UINT_FMT"\n", locator->phys_addr);
        return -1;
    }

    return 0;
}

static int smbios_locate_structures(struct smbios_locator *locator)
{
    size_t loc = 0;
    uint8_t *addr;
    int rc = -1;

    memset(locator, 0, sizeof(struct smbios_locator));

    /* use EFI tables if present */
    rc = find_efi_entry_location("SMBIOS", 6, &loc);
    if ( (rc == 0) && (loc != 0) ) {
        addr = map_phys_mem(loc, SMBIOS_SM_LENGTH);
        if ( addr == NULL )
        {
            xcpmd_log(LOG_ERR, "Failed to map SMBIOS entry point structure at phys="UINT_FMT"\n", loc);
            return -1;
        }
        rc = smbios_entry_point(locator, addr, 1);
        unmap_phys_mem(addr, SMBIOS_SM_LENGTH);
        return rc;
    }

    /* Locate SMBIOS entry via memory scan of ROM region */
    addr = map_phys_mem(SCAN_ROM_BIOS_BASE, SCAN_ROM_BIOS_SIZE);
    if ( addr == NULL )
    {
        xcpmd_log(LOG_ERR, "Failed to map ROM BIOS at phys=%x\n", SCAN_ROM_BIOS_BASE);
        return -1;
    }

    for ( loc = 0; loc <= (SCAN_ROM_BIOS_SIZE - SMBIOS_SM_LENGTH); loc += 16 ) { /* stop before 0xFFE0 */
        /* Look for _SM_ signature for newer entry point which preceeds _DMI_, else look for only the older _DMI_ */
        if ( memcmp(addr + loc, "_SM_", 4) == 0 )
        {
            rc = smbios_entry_point(locator, addr + loc, 1);
            if ( rc == 0 ) /* found it */
                break;
        }
        else if ( memcmp(addr + loc, "_DMI_", 5) == 0 )
        {
            rc = smbios_entry_point(locator, addr + loc, 0);
            if ( rc == 0 ) /* found it */
                break;
        }
    }
    unmap_phys_mem(addr, SCAN_ROM_BIOS_SIZE);

    return rc;
}

static void *smbios_locate_structure_instance(struct smbios_locator *locator,
                                              uint8_t type, uint32_t instance,
                                              uint32_t *length_out)
{
    uint16_t idx;
    uint8_t *ptr = locator->addr;
    uint8_t *tail;
    uint32_t counter = 0;
    void *table = NULL;

    for ( idx = 0; idx < locator->count; idx++ )
    {
        if ( (ptr[SMBIOS_STRUCT_LENGTH] < 4)||
           ( (ptr + ptr[SMBIOS_STRUCT_LENGTH]) > (ptr + locator->length)) )
        {
            xcpmd_log(LOG_ERR, "Invalid SMBIOS table data detected\n");
            return NULL;
        }

        /* Run the tail pointer past the end of this struct and all strings */
        tail = ptr + ptr[SMBIOS_STRUCT_LENGTH];
        while ( (tail - ptr + 1) < locator->length )
        {
            if ( (tail[0] == 0) && (tail[1] == 0) )
                break;
            tail++;
        }
        tail += 2;

        if ( (ptr[SMBIOS_STRUCT_TYPE] == type) && (++counter == instance) )
        {
            table = ptr;
            if ( length_out != NULL )
                *length_out = (tail - ptr);

            break;
        }

        /* test for terminating structure */
        if ( ptr[SMBIOS_STRUCT_TYPE] == SMBIOS_TYPE_EOT )
        {
            /* table is done - sanity check */
            if ( idx != locator->count - 1 )
            {
                xcpmd_log(LOG_ERR, "SMBIOS missing EOT at end\n");
                return NULL;
            }
        }

        ptr = tail;
    }

    return table;
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
