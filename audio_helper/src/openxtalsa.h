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

#ifndef OPENXTALSA_H
#define OPENXTALSA_H

#define ALSA_PCM_NEW_HW_PARAMS_API
#include <alsa/asoundlib.h>

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#define MAX_NAME_LENGTH 256

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

typedef struct Settings {

    snd_pcm_t *handle;
    snd_pcm_stream_t stream;

    snd_mixer_t *mhandle;
    snd_mixer_elem_t *elem;

    int32_t fmt;
    uint32_t freq;
    int32_t mode;
    int32_t valid;
    uint32_t nchannels;
    int32_t sample_size;

    char pcm_name[MAX_NAME_LENGTH];

    char selement_name[MAX_NAME_LENGTH];
    long selement_index;

} Settings;

// Global
int openxt_alsa_set_card(int32_t n);
int openxt_alsa_set_device(char *name);

// Settings
int openxt_alsa_create(Settings **settings);
int openxt_alsa_destroy(Settings *settings);

// PCM
int openxt_alsa_fini(Settings *settings);
int openxt_alsa_init(Settings *settings);
int openxt_alsa_prepare(Settings *settings);
int openxt_alsa_drop(Settings *settings);
int openxt_alsa_start(Settings *settings);
int openxt_alsa_get_available(Settings *settings);
int openxt_alsa_writei(Settings *settings, void *buffer, int32_t num, int32_t size);
int openxt_alsa_readi(Settings *settings, void *buffer, int32_t num, int32_t size);

// Simple Mixer
int openxt_alsa_mixer_fini(Settings *settings);
int openxt_alsa_mixer_init(Settings *settings);
int openxt_alsa_mixer_print_selement(Settings *settings);
int openxt_alsa_mixer_print_selements(Settings *settings);
int openxt_alsa_mixer_sget(Settings *settings);
int openxt_alsa_mixer_sset_enum(Settings *settings, char *name);
int openxt_alsa_mixer_sset_volume(Settings *settings, int32_t vol);
int openxt_alsa_mixer_sset_switch(Settings *settings, int32_t enabled);

// Control
int openxt_alsa_remove_pcm(Settings *settings);

// Helper
int openxt_alsa_percentage(Settings *settings, int32_t vol);

#endif // OPENXTALSA_H
