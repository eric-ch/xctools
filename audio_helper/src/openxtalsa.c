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

#include <math.h>

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Global Variables                                                                                    //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

static char device[256] = "default";

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Global Functions                                                                                    //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

///
/// Set's the device name for the mixer APIs
///
/// @param n the card #
/// @return -EINVAL if n < 0
///         -EINVAL if n >= 32
///         negative error code on failure
///         0 on success
///
int openxt_alsa_set_card(int32_t n)
{
    int ret;

    // Sanity checks
    openxt_assert(n >= 0, -EINVAL);
    openxt_assert(n < 32, -EINVAL);

    // Copy the name to the global device name
    ret = snprintf(device, sizeof(device), "hw:%i", n);
    openxt_assert_ret(ret >= 0, ret, ret);

    // Done
    return 0;
}

///
/// Set's the device name for the mixer APIs
///
/// @param name the name of the device
/// @return -EINVAL name == NULL
///         -EINVAL name larger than 256 bytes
///         negative error code on failure
///         0 on success
///
int openxt_alsa_set_device(char *name)
{
    int ret;

    // Sanity checks
    openxt_checkp(name, -EINVAL);
    openxt_assert(strlen(name) < sizeof(device), -EINVAL);

    // Copy the name to the global device name
    ret = snprintf(device, sizeof(device), "%s", name);
    openxt_assert_ret(ret >= 0, ret, ret);

    // Done
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Settings Functions                                                                                  //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

///
/// Create a setting's structure. Once created this needs to be filled in by
/// the user as it will be used by all of the ALSA APIs.
///
/// @param settings pointer to the settings structure to be created
/// @return -EINVAL settings == NULL
///         -EINVAL *settings != NULL
///         -ENOMEM if out of memory
///         0 on success
///
int openxt_alsa_create(Settings **settings)
{
    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_assert(*settings == NULL, -EINVAL);

    // Allocate the settings variable.
    *settings = (Settings *)calloc(1, sizeof(Settings));

    // Make sure that the memory was allocated. (This really should never happen)
    if (*settings == NULL)
        return -ENOMEM;

    // Done
    return 0;
}

///
/// Destroy a settings structure that we previously created.
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL if the pcm handle is still open
///         -EINVAL if the mixer handler is still open
///         0 on success, or if the settings structure is already NULL
///
int openxt_alsa_destroy(Settings *settings)
{
    // Ignore if the settings structure is already destroyed
    if (settings == NULL)
        return 0;

    // Sanity checks
    openxt_assert(settings->handle == NULL, -EINVAL);
    openxt_assert(settings->mhandle == NULL, -EINVAL);

    // Cleanup memory
    free(settings);

    // Done
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// PCM Functions                                                                                       //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

///
/// Close a previously initialized PCM device
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_fini(Settings *settings)
{
    int ret = 0;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);

    // Cleanup
    if (settings->handle != NULL)
        ret = snd_pcm_close(settings->handle);

    // Reset
    settings->handle = NULL;

    // Done
    return ret;
}

///
/// Initialize the PCM device that is provided in the settings structure
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         negative error code on failure
///         0 on success, or is the PCM is already initialized
///
int openxt_alsa_init(Settings *settings)
{
    int ret;
    snd_pcm_hw_params_t *hw_params = NULL;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_assert_quiet(settings->handle == NULL, 0);

    // ALSA BUG: This is a bug with ALSA, that can be easily reproduced.
    // Basically when using the "softvol" plugin (like we do), the plugin
    // ends up locking the PCM when it is created once opened, and this lock
    // cannot be removed (you get an EPERM when you attempt to unlock). For
    // now, the easy solution is to open the PCM, close it, and re-open it.
    // For whatever reason, when you re-open the PCM, it's state is normal.
    ret = snd_pcm_open(&(settings->handle), settings->pcm_name, settings->stream, settings->mode);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = snd_pcm_close(settings->handle);
    openxt_assert_ret(ret == 0, ret, ret);

    // Open the ALSA device for this VM, and allocate an opaque buffer to store
    // the parameters that are used to setup ALSA. Note that a lot of the examples
    // use the alloca version, but we found that it had issues with the stack, so
    // this code uses the malloc version.
    ret = snd_pcm_open(&(settings->handle), settings->pcm_name, settings->stream, settings->mode);
    openxt_assert_ret(ret == 0, ret, ret);

    // Create the hardware param object. We will fill this object with a the
    // audio settings, and then provide that to ALSA. Note that we use the
    // malloc
    ret = snd_pcm_hw_params_malloc(&hw_params);
    openxt_assert_goto(ret == 0, failure);

    // Use the provided settings to setup ALSA. Note that we don't validate the
    // samples size with provided format. We basically assume that the user has
    // that figured out.
    ret = snd_pcm_hw_params_any(settings->handle, hw_params);
    openxt_assert_goto(ret == 0, failure);
    ret = snd_pcm_hw_params_set_access(settings->handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED);
    openxt_assert_goto(ret == 0, failure);
    ret = snd_pcm_hw_params_set_format(settings->handle, hw_params, settings->fmt);
    openxt_assert_goto(ret == 0, failure);
    ret = snd_pcm_hw_params_set_rate(settings->handle, hw_params, settings->freq, 0);
    openxt_assert_goto(ret == 0, failure);
    ret = snd_pcm_hw_params_set_channels(settings->handle, hw_params, settings->nchannels);
    openxt_assert_goto(ret == 0, failure);

    // The following commits these settings.
    ret = snd_pcm_hw_params(settings->handle, hw_params);
    openxt_assert_goto(ret == 0, failure);

    // The final step is to get the settings from ALSA and store them back into the
    // settings structure. This way, if ALSA has changed anything, the caller can see
    // that and handle it as needed.
    ret = snd_pcm_hw_params_get_format(hw_params, &settings->fmt);
    openxt_assert_goto(ret == 0, failure);
    ret = snd_pcm_hw_params_get_rate(hw_params, &settings->freq, 0);
    openxt_assert_goto(ret == 0, failure);
    ret = snd_pcm_hw_params_get_channels(hw_params, &settings->nchannels);
    openxt_assert_goto(ret == 0, failure);

    // Cleanup
    snd_pcm_hw_params_free(hw_params);

    // Success
    return 0;

failure:

    // Cleanup
    if (hw_params != NULL)
        snd_pcm_hw_params_free(hw_params);

    // Safety
    openxt_alsa_fini(settings);

    // Failure
    return ret;
}

///
/// Prepare the ALSA PCM
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL PCM closed
///         negative error code on failure
///         0 on success
///
int openxt_alsa_prepare(Settings *settings)
{
    // Sanity check
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->handle, -EINVAL);

    // Prepare ALSA
    return snd_pcm_prepare(settings->handle);
}

///
/// Drop remaining samples in the PCM
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL PCM closed
///         negative error code on failure
///         0 on success
///
int openxt_alsa_drop(Settings *settings)
{
    // Sanity check
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->handle, -EINVAL);

    // Prepare ALSA
    return snd_pcm_drop(settings->handle);
}

///
/// Start the ALSA PCM (for capture)
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL PCM closed
///         negative error code on failure
///         0 on success
///
int openxt_alsa_start(Settings *settings)
{
    // Sanity check
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->handle, -EINVAL);

    // Prepare ALSA
    return snd_pcm_start(settings->handle);
}

///
/// Get the available samples in the PCM
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL PCM closed
///         negative error code on failure
///         # of available samples on success
///         0 on failure or no available samples
///
int openxt_alsa_get_available(Settings *settings)
{
    int ret;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->handle, -EINVAL);

    // We add this loop here because if we get an EPIPE error, we need to
    // try again, and this provides an easy way to do that.
    while(1) {

        if ((ret = snd_pcm_avail(settings->handle)) < 0) {

            // Check for EPIPE (xrun / suspended). If this is the case, we
            // restart ALSA and try again.
            if (ret == -EPIPE) {
                ret = openxt_alsa_prepare(settings);
                openxt_assert_ret(ret == 0, ret, ret);
                continue;
            }

            // If we got this far, we got have an error.
            openxt_error("snd_pcm_avail failed: %d - %s\n", ret, snd_strerror(ret));

            // If this happens, no samples are available
            ret = 0;
        }

        // Done
        break;
    }

    // Return the number of samples
    return ret;
}

///
/// Write samples to the PCM
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL buffer == NULL
///         -EINVAL PCM closed
///         -EINVAL number of samples > size of buffer
///         negative error code on failure
///         number of samples written on success
///
int openxt_alsa_writei(Settings *settings, void *buffer, int32_t num, int32_t size)
{
    int ret;

    // Sanity checks
    openxt_checkp(buffer, -EINVAL);
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->handle, -EINVAL);
    openxt_assert(settings->sample_size * num <= size, -EINVAL);

    // No need to run this if we are writing 0 samples
    if (num <= 0)
        return 0;

    // We add this loop here because if we get an EPIPE error, we need to
    // try again, and this provides an easy way to do that.
    while(1) {

        if ((ret = snd_pcm_writei(settings->handle, buffer, num)) < 0) {

            // Check for EPIPE (xrun / suspended). If this is the case, we
            // restart ALSA and try again.
            if (ret == -EPIPE) {
                ret = openxt_alsa_prepare(settings);
                openxt_assert_ret(ret == 0, ret, ret);
                continue;
            }

            // If the error is EAGAIN, it means that we are in non-blocking
            // mode, and that we should try again later. In this case, we
            // report 0 bytes.
            if (ret == -EAGAIN) {
                ret = 0;
                break;
            }

            // If we got this far, we got have an error.
            openxt_error("snd_pcm_writei failed: %d - %s\n", ret, snd_strerror(ret));
            break;
        }

        // Done
        break;
    }

    // Done
    return ret;
}

///
/// Read samples from the PCM
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL buffer == NULL
///         -EINVAL PCM closed
///         -EINVAL number of samples > size of buffer
///         negative error code on failure
///         number of samples read on success
///
int openxt_alsa_readi(Settings *settings, void *buffer, int32_t num, int32_t size)
{
    int ret;

    // Sanity checks
    openxt_checkp(buffer, -EINVAL);
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->handle, -EINVAL);
    openxt_assert(settings->sample_size * num <= size, -EINVAL);

    // No need to run this if we are reading 0 samples
    if (num <= 0)
        return 0;

    // We add this loop here because if we get an EPIPE error, we need to
    // try again, and this provides an easy way to do that.
    while(1) {

        if ((ret = snd_pcm_readi(settings->handle, buffer, num)) < 0) {

            // Check for EPIPE (xrun / suspended). If this is the case, we
            // restart ALSA and try again.
            if (ret == -EPIPE) {
                ret = openxt_alsa_prepare(settings);
                openxt_assert_ret(ret == 0, ret, ret);
                continue;
            }

            // If the error is EAGAIN, it means that we are in non-blocking
            // mode, and that we should try again later. In this case, we
            // report 0 bytes.
            if (ret == -EAGAIN) {
                ret = 0;
                break;
            }

            // If we got this far, we got have an error.
            openxt_error("snd_pcm_readi failed: %d - %s\n", ret, snd_strerror(ret));
            break;
        }

        // Done
        break;
    }

    // Done
    return ret;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Simple Element Functions                                                                            //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

///
/// Initialize the mixer
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_fini(Settings *settings)
{
    int ret = 0;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);

    // Cleanup
    if (settings->mhandle != NULL){

        // Cleanup
        snd_mixer_free(settings->mhandle);

        // Close the mixer handle
        ret = snd_mixer_close(settings->mhandle);
    }

    // Reset
    settings->mhandle = NULL;

    // Done
    return ret;

}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_init(Settings *settings)
{
    int ret;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_assert_quiet(settings->mhandle == NULL, 0);

    // Setup the handle
    ret = snd_mixer_open(&settings->mhandle, 0);
    openxt_assert_goto(ret == 0, falure);
    ret = snd_mixer_attach(settings->mhandle, device);
    openxt_assert_goto(ret == 0, falure);
    ret = snd_mixer_selem_register(settings->mhandle, NULL, NULL);
    openxt_assert_goto(ret == 0, falure);
    ret = snd_mixer_load(settings->mhandle);
    openxt_assert_goto(ret == 0, falure);

    // Success
    return 0;

falure:

    // Safety
    openxt_alsa_mixer_fini(settings);

    // Failure
    return ret;
}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_print_selement(Settings *settings)
{
    int ret = 0;
    int btn = 0;
    long vol = 0;
    char type = 'D';
    bool has_volume = false;
    bool has_switch = false;

    char name_string[256] = {0};
    char volume_string[256] = {0};
    char switch_string[256] = {0};

    snd_mixer_selem_id_t *sid = NULL;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->elem, -EINVAL);
    openxt_checkp(settings->mhandle, -EINVAL);

    // Create a simple element id for this element, and then get the
    // id from the element. This is needed to get the index and name
    // from the element
    ret = snd_mixer_selem_id_malloc(&sid);
    openxt_assert_ret(ret == 0, ret, ret);

    // Get the name and index
    snd_mixer_selem_get_id(settings->elem, sid);

    // Create the name string for this element. Note that if the
    // element's index is greater than 0, they append a number to
    // the name with a comma. I think this is so that you can have
    // more than one element with the same name, but still be able
    // to uniquely identify them.
    if (snd_mixer_selem_id_get_index(sid) > 0) {
        snprintf(name_string, sizeof(name_string), "%s,%d", snd_mixer_selem_id_get_name(sid),
                                                            snd_mixer_selem_id_get_index(sid));
    } else {
        snprintf(name_string, sizeof(name_string), "%s", snd_mixer_selem_id_get_name(sid));
    }

    // We are done with the id. Freeing it here prevents the need for
    // a bunch of goto statements.
    snd_mixer_selem_id_free(sid);

    // Type: Defines whether this is a capture device (C), a playback device (P),
    // or both (D). ALSA annoying doesn't have an API call to ask which type it
    // is so your going to see some assumptions. This is because you can also have
    // a device that has a switch and no volume, no switch and volume, and both
    // so we have to set the type more than once to account for these different
    // situations.

    // Volume
    if (snd_mixer_selem_has_common_volume(settings->elem)) {
        type = 'D';
        has_volume = true;
    }
    else
    {
        if (snd_mixer_selem_has_playback_volume(settings->elem)) {
            type = 'P';
            has_volume = true;
        }
        else if (snd_mixer_selem_has_capture_volume(settings->elem)) {
            type = 'C';
            has_volume = true;
        }
    }

    // Switch
    if (snd_mixer_selem_has_common_switch(settings->elem)) {
        type = 'D';
        has_switch = true;
    }
    else
    {
        if (snd_mixer_selem_has_playback_switch(settings->elem)) {
            type = 'P';
            has_switch = true;
        }
        else if (snd_mixer_selem_has_capture_switch(settings->elem)) {
            type = 'C';
            has_switch = true;
        }
    }

    // Volume: Now that we know what type of simple element that we are dealing
    // with, we need to get the volume of this element (assuming that it has
    // volume). This application only supports mono volume control, which means
    // that the controls we care about are either the MONO channel, or the LEFT
    // channel (as the left channel is considered the mono portion of stereo).
    // Also note that the ALSA documentation states that LEFT and MONO are the
    // same thing
    if (has_volume) {
        switch(type) {
            case 'D':
            case 'P':
            {
                if (snd_mixer_selem_has_playback_channel(settings->elem, SND_MIXER_SCHN_MONO)) {
                    ret = snd_mixer_selem_get_playback_volume(settings->elem, SND_MIXER_SCHN_MONO, &vol);
                    openxt_assert_ret(ret == 0, ret, ret);
                    break;
                }
                break;
            }
            case 'C':
            {
                if (snd_mixer_selem_has_capture_channel(settings->elem, SND_MIXER_SCHN_MONO)) {
                    ret = snd_mixer_selem_get_capture_volume(settings->elem, SND_MIXER_SCHN_MONO, &vol);
                    openxt_assert_ret(ret == 0, ret, ret);
                    break;
                }
                break;
            }
            default:
                break;
        }
    }

    // Switch: The switch is in a similar boat in that it can have multiple
    // channels, but we only support mono so we use the MONO channel or the
    // LEFT channel.
    if (has_switch) {
        switch(type) {
            case 'D':
            case 'P':
            {
                if (snd_mixer_selem_has_playback_channel(settings->elem, SND_MIXER_SCHN_MONO)) {
                    ret = snd_mixer_selem_get_playback_switch(settings->elem, SND_MIXER_SCHN_MONO, &btn);
                    openxt_assert_ret(ret == 0, ret, ret);
                    break;
                }
                break;
            }
            case 'C':
            {
                if (snd_mixer_selem_has_capture_channel(settings->elem, SND_MIXER_SCHN_MONO)) {
                    ret = snd_mixer_selem_get_capture_switch(settings->elem, SND_MIXER_SCHN_MONO, &btn);
                    openxt_assert_ret(ret == 0, ret, ret);
                    break;
                }
                break;
            }
            default:
                break;
        }
    }

    // Now that we know the volume and the switch, we need to convert
    // these values into strings so that they be printed. First we start
    // with the volume, which needs to be converted into a percentage,
    // so we need to know what that the min and max is so that we can
    // calculate this percentage.
    if (has_volume) {

        int ret;

        // Get the percentage
        ret = openxt_alsa_percentage(settings, vol);
        openxt_assert_ret(ret >= 0, ret, ret);

        // Create the string version of this percentage
        snprintf(volume_string, sizeof(volume_string), "%d%%", ret);
    }

    // Converting the switch to a string is pretty simple
    if (has_switch) {
        if (btn) {
            snprintf(switch_string, sizeof(switch_string), "on");
        } else {
            snprintf(switch_string, sizeof(switch_string), "off");
        }
    }

    // Finally, print the resulting element. Note that this print statement
    // is very specific as it is what xenmgr is expecting. If you modify what
    // this application prints to the screen, you will also need to update
    // the tool stack.

    openxt_info("%c '%s' ", type, name_string)

    // Volume / Switch
    if (has_volume) {
        if (has_switch) {
            openxt_info("VS %s %s", volume_string, switch_string);
        } else {
            openxt_info("VO %s", volume_string);
        }
    } else {
        if (has_switch) {
            openxt_info("SW %s", switch_string);
        }
    }

    // Enum
    if (snd_mixer_selem_is_enumerated(settings->elem)) {

        int i;
        unsigned int idx;
        char enum_string[256];

        // Tell xenmgr that this data is part of an enum
        openxt_info("EN");

        // Print the current item
        if (snd_mixer_selem_get_enum_item(settings->elem, SND_MIXER_SCHN_MONO, &idx) == 0) {
            ret = snd_mixer_selem_get_enum_item_name(settings->elem, idx, sizeof(enum_string), enum_string);
            openxt_assert_ret(ret == 0, ret, ret);
            openxt_info(" current:'%s'", enum_string);
        }

        // Print the possible options
        for (i = 0; i < snd_mixer_selem_get_enum_items(settings->elem); i++) {
            ret = snd_mixer_selem_get_enum_item_name(settings->elem, i, sizeof(enum_string), enum_string);
            openxt_assert_ret(ret == 0, ret, ret);
            openxt_info(" '%s'", enum_string);
        }
    }

    openxt_info("\n");

    // Done
    return 0;
}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_print_selements(Settings *settings)
{
    int ret = 0;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->mhandle, -EINVAL);

    // Get the firs element.
    settings->elem = snd_mixer_first_elem(settings->mhandle);

    // Loop through all of the elements, and print their contents.
    while (settings->elem) {

        // Print the contents of the simple element.
        ret = openxt_alsa_mixer_print_selement(settings);
        openxt_assert_ret(ret == 0, ret, ret);

        // Get the next element.
        settings->elem = snd_mixer_elem_next(settings->elem);
    }

    // If we got here, it means that there is no simple elements.
    // In this case we say it succeeded.
    return 0;
}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_sget(Settings *settings)
{
    int ret;
    snd_mixer_selem_id_t *selem_id = NULL;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->mhandle, -EINVAL);

    // Create a simple element id. For whatever reason, if you want to search
    // for a simple element, you need to define the selement id, and then set
    // the name there so that you can do the search
    ret = snd_mixer_selem_id_malloc(&selem_id);
    openxt_assert_ret(ret == 0, ret, ret);

    // Set the name and index of the simple element id. Note that usually the
    // index will be 0, but it can be something else. A good example of this is
    // the Capture,1 element, who's index is 1 and not 0. Also note that there
    // is no return value for these functions.
    snd_mixer_selem_id_set_name(selem_id, settings->selement_name);
    snd_mixer_selem_id_set_index(selem_id, settings->selement_index);

    // Get the simple element
    settings->elem = snd_mixer_find_selem(settings->mhandle, selem_id);
    openxt_checkp_goto(settings->elem, failure);

    // Success
    snd_mixer_selem_id_free(selem_id);
    return 0;

failure:

    // Failure
    snd_mixer_selem_id_free(selem_id);
    return -ENOENT;
}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_sset_enum(Settings *settings, char *name)
{
    int i;
    int ret;
    char enum_string[256];

    // Sanity checks
    openxt_checkp(name, -EINVAL);
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->elem, -EINVAL);
    openxt_assert(snd_mixer_selem_is_enumerated(settings->elem), -EINVAL);

    // Print the possible options
    for (i = 0; i < snd_mixer_selem_get_enum_items(settings->elem); i++) {
        ret = snd_mixer_selem_get_enum_item_name(settings->elem, i, sizeof(enum_string), enum_string);
        openxt_assert_ret(ret == 0, ret, ret);

        // If this is the element, stop looking.
        if (strncmp(enum_string, name, min(sizeof(enum_string), strlen(name))) == 0)
            break;
    }

    // Make sure that we found the enum
    if (i >= snd_mixer_selem_get_enum_items(settings->elem))
        return -EINVAL;

    // Set the enum
    ret = snd_mixer_selem_set_enum_item(settings->elem, SND_MIXER_SCHN_MONO, i);
    openxt_assert_ret(ret == 0, ret, ret);

    // Success
    return 0;
}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_sset_volume(Settings *settings, int32_t vol)
{
    int ret;
    int chn;
    long min;
    long max;
    char type = 0;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->elem, -EINVAL);
    openxt_assert(vol >= 0 && vol <= 100, -EINVAL);

    // Figure out if this is a playback element
    if (snd_mixer_selem_has_common_volume(settings->elem) == 1 ||
        snd_mixer_selem_has_playback_volume(settings->elem) == 1) {
        type = 'P';
    }

    // Figure out if this is a capture element
    else if (snd_mixer_selem_has_capture_volume(settings->elem) == 1) {
        type = 'C';
    }

    // Not supported
    else {
        return 0;
    }

    // We need to get the actual range that ALSA has setup for the simple
    // element. This function accepts a percentage (0-100) so we need to
    // convert
    switch(type) {
        case 'P':
            ret = snd_mixer_selem_get_playback_volume_range(settings->elem, &min, &max);
            openxt_assert_ret(ret == 0, ret, ret);
            break;
        case 'C':
            ret = snd_mixer_selem_get_capture_volume_range(settings->elem, &min, &max);
            openxt_assert_ret(ret == 0, ret, ret);
            break;
        default:
            break;
    }

    // Now that we have the max and min, we can calculate the volume .
    // Note that we don't support setting each channel manually, you set the
    // volume for all of the channels.
    vol = round(((double)((max - min) * vol)) / 100.0);

    // Loop through all of the channles, and their their volume as well
    // as their switch
    for (chn = 0; chn <= SND_MIXER_SCHN_LAST; chn++) {

        switch(type) {
            case 'P':
                ret = snd_mixer_selem_set_playback_volume(settings->elem, chn, vol);
                openxt_assert_ret(ret == 0, ret, ret);
                break;
            case 'C':
                ret = snd_mixer_selem_set_capture_volume(settings->elem, chn, vol);
                openxt_assert_ret(ret == 0, ret, ret);
                break;
            default:
                break;
        }
    }

    // Success
    return 0;
}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_mixer_sset_switch(Settings *settings, int32_t enabled)
{
    int ret;
    int chn;
    char type = 0;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->elem, -EINVAL);

    // Figure out if this is a playback element
    if (snd_mixer_selem_has_common_switch(settings->elem) == 1 ||
        snd_mixer_selem_has_playback_switch(settings->elem) == 1) {
        type = 'P';
    }

    // Figure out if this is a capture element
    else if (snd_mixer_selem_has_capture_switch(settings->elem) == 1) {
        type = 'C';
    }

    // Not supported
    else {
        return 0;
    }

    // Loop through all of the channles, and their their volume as well
    // as their switch
    for (chn = 0; chn <= SND_MIXER_SCHN_LAST; chn++) {

        switch(type) {
            case 'P':
                ret = snd_mixer_selem_set_playback_switch(settings->elem, chn, enabled);
                openxt_assert_ret(ret == 0, ret, ret);
                break;
            case 'C':
                ret = snd_mixer_selem_set_capture_switch(settings->elem, chn, enabled);
                openxt_assert_ret(ret == 0, ret, ret);
                break;
            default:
                break;
        }
    }

    // Success
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Control Functions                                                                                   //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_remove_pcm(Settings *settings)
{
    int ret;
    snd_ctl_t *ctl = NULL;
    snd_ctl_elem_id_t *eid = NULL;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);

    // Open the ALSA control interface
    ret = snd_ctl_open(&ctl, device, 0);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = snd_ctl_elem_id_malloc(&eid);
    openxt_assert_goto(ret == 0, failure);

    // Set the control inter face name and type
    snd_ctl_elem_id_set_interface(eid, SND_CTL_ELEM_IFACE_MIXER);
    snd_ctl_elem_id_set_name(eid, settings->selement_name);
    snd_ctl_elem_id_set_index(eid, settings->selement_index);

    // Remove the PCM
    ret = snd_ctl_elem_remove(ctl, eid);
    openxt_assert_goto(ret == 0, failure);

    // Cleanup
    snd_ctl_elem_id_free(eid);
    snd_ctl_close(ctl);

    // Success
    return 0;

failure:

    // Cleanup
    if (eid != NULL) snd_ctl_elem_id_free(eid);
    if (ctl != NULL) snd_ctl_close(ctl);

    // Success
    return ret;
}

///
///
///
/// @param settings a pointer to the settings structure
/// @return -EINVAL settings == NULL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
int openxt_alsa_percentage(Settings *settings, int32_t vol)
{
    int ret;
    long min;
    long max;

    // Sanity checks
    openxt_checkp(settings, -EINVAL);
    openxt_checkp(settings->elem, -EINVAL);
    openxt_checkp(settings->mhandle, -EINVAL);

    // Get the range of the simple element (for playback or common)
    if (snd_mixer_selem_has_common_volume(settings->elem) ||
        snd_mixer_selem_has_playback_volume(settings->elem)) {
        ret = snd_mixer_selem_get_playback_volume_range(settings->elem, &min, &max);
        openxt_assert_ret(ret == 0, ret, ret);
    }

    // Get the range of the simple element (for capture)
    if (snd_mixer_selem_has_capture_volume(settings->elem)) {
        ret = snd_mixer_selem_get_capture_volume_range(settings->elem, &min, &max);
        openxt_assert_ret(ret == 0, ret, ret);
    }

    // Return the percentage.
    return round(((double)(vol * 100)) / ((double)(max - min)));
}
