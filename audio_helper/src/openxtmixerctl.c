//
// Copyright (c) 2015 Assured Information Security, Inc
//
// Dates Modified:
//  - 4/8/2015: Initial commit
//    Rian Quinn <quinnr@ainfosec.com>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "openxtalsa.h"
#include "openxtdebug.h"
#include "openxtmixerctl.h"

///
///
///
/// @param
/// @return -EINVAL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_mixer_ctl_scontrols(int argc, char *argv[])
{
    // The original amixer patch did this, were this command was basically the
    // same as scontents. To prevent a potential modification to the tool
    // stack, I left it the same here as well.
    return openxt_mixer_ctl_scontents(argc, argv);
}

///
///
///
/// @param
/// @return -EINVAL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_mixer_ctl_scontents(int argc, char *argv[])
{
    int ret = 0;
    Settings *settings = NULL;

    (void)argc;
    (void)argv;

    // Create the settings structures.
    ret = openxt_alsa_create(&settings);
    openxt_assert_ret(ret == 0, ret, ret);

    // Initialize the mixer
    ret = openxt_alsa_mixer_init(settings);
    openxt_assert_goto(ret == 0, done);

    // Print the simple elements
    ret = openxt_alsa_mixer_print_selements(settings);
    openxt_assert_goto(ret == 0, done);

done:

    // Close the mixer
    openxt_alsa_mixer_fini(settings);

    // Destroy the settings
    openxt_alsa_destroy(settings);
    settings = NULL;

    // Done
    return ret;
}

///
///
///
/// @param
/// @return -EINVAL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_mixer_parse_name(Settings *settings, char *name)
{
    int n = 0;
    char *index = NULL;

    // Sanity checks
    openxt_checkp(name, -EINVAL);
    openxt_checkp(settings, -EINVAL);

    // Figure out if we have an index or not. If we do, we need to
    // split the string.
    index = strchr(name, ',');
    if (index && strlen(index) > 1) {

        // Skip the ","
        index++;

        // Get the size of the name portion of the string. Note that the
        // strchr function returns the string after the first occurrence
        // of our search character. We can use that pointer to calculate
        // the total size of the first part
        n = min(index - name - 1, MAX_NAME_LENGTH);

        // Store the index
        settings->selement_index = atoi(index);

        // Store the name
        memcpy(settings->selement_name, name, n);

    } else {

        // Store the index
        settings->selement_index = 0;

        // Store the name
        strncpy(settings->selement_name, name, MAX_NAME_LENGTH - 1);
    }

    // Done
    return 0;
}

///
///
///
/// @param
/// @return -EINVAL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_mixer_ctl_sset(int argc, char *argv[])
{
    int i = 0;
    int ret = 0;
    int enabled = -1;
    int percentage = -1;
    Settings *settings = NULL;

    // Make sure that we got the correct number of arguments.
    if (argc <= optind + 2) {
        openxt_info("wrong syntax: expecting %s <options> sget sID P [on/off]\n", argv[0]);
        return -EINVAL;
    }

    // Create the settings structures.
    ret = openxt_alsa_create(&settings);
    openxt_assert_ret(ret == 0, ret, ret);

    // Initialize the mixer
    ret = openxt_alsa_mixer_init(settings);
    openxt_assert_goto(ret == 0, done);

    // Parse the name
    ret = openxt_mixer_parse_name(settings, argv[optind + 1]);
    openxt_assert_goto(ret == 0, done);

    // Get the element that the user provided.
    ret = openxt_alsa_mixer_sget(settings);
    openxt_assert_goto(ret == 0, done);

    // If this is an enum, we have to treat it differently. In this case, we only
    // support one argument, and that is treated as the enum itself. Otherwise,
    // we need to treat this as a volume setting, and handle it correctly.
    if (snd_mixer_selem_is_enumerated(settings->elem)) {

        ret = openxt_alsa_mixer_sset_enum(settings, argv[optind + 2]);
        openxt_assert_goto(ret == 0, done);

    } else {

        // Loop through the remaining parameters and figure out what they are
        // They could be:
        // - volume value
        // - volume percentage
        // - on/off
        for (i = optind + 2; i < argc; i++)
        {
            // Check to see if this is "on"
            if (strncmp(argv[i], "on", min(strlen(argv[i]), strlen("on"))) == 0) {
                enabled = 1;
                continue;
            }

            // Check to see if this is "off"
            if (strncmp(argv[i], "off", min(strlen(argv[i]), strlen("off"))) == 0) {
                enabled = 0;
                continue;
            }

            // If we got this far, we assume that it's a number. We need to
            // see if the number is a percentage.
            if (strstr(argv[i], "%") != NULL) {

                char number[256] = { 0 };

                // Copy up to the %
                strncpy(number, strtok(argv[i],"%"), sizeof(number) - 1);

                // Store the percentage
                percentage = atoi(number);

            } else {

                // We need to convert the volume to a percentage since our ALSA
                // wrappers expect a percentage.
                ret = openxt_alsa_percentage(settings, atoi(argv[i]));
                openxt_assert_goto(ret >= 0, done);

                // Store the percentage
                percentage = ret;
            }
        }

        // Cleanup the percentage
        percentage = max(percentage, 0);
        percentage = min(percentage, 100);

        // Finally set the volume and switch
        if (enabled >= 0) openxt_alsa_mixer_sset_switch(settings, enabled);
        if (percentage >= 0) openxt_alsa_mixer_sset_volume(settings, percentage);
    }

    // Print the element
    ret = openxt_alsa_mixer_print_selement(settings);
    openxt_assert_goto(ret == 0, done);

done:

    // Close the mixer
    openxt_alsa_mixer_fini(settings);

    // Destroy the settings
    openxt_alsa_destroy(settings);
    settings = NULL;

    // Done
    return ret;
}

///
///
///
/// @param
/// @return -EINVAL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_mixer_ctl_sget(int argc, char *argv[])
{
    int ret = 0;
    Settings *settings = NULL;

    // Make sure that we got the correct number of arguments.
    if (argc != optind + 2) {
        openxt_info("wrong syntax: expecting %s <options> sget sID\n", argv[0]);
        return -EINVAL;
    }

    // Create the settings structures.
    ret = openxt_alsa_create(&settings);
    openxt_assert_ret(ret == 0, ret, ret);

    // Initialize the mixer
    ret = openxt_alsa_mixer_init(settings);
    openxt_assert_goto(ret == 0, done);

    // Parse the name
    ret = openxt_mixer_parse_name(settings, argv[optind + 1]);
    openxt_assert_goto(ret == 0, done);

    // Get the element that the user provided.
    ret = openxt_alsa_mixer_sget(settings);
    openxt_assert_goto(ret == 0, done);

    // Print the element
    ret = openxt_alsa_mixer_print_selement(settings);
    openxt_assert_goto(ret == 0, done);

done:

    // Close the mixer
    openxt_alsa_mixer_fini(settings);

    // Destroy the settings
    openxt_alsa_destroy(settings);
    settings = NULL;

    // Done
    return ret;
}
