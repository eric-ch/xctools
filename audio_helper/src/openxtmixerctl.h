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

#ifndef OPENXT_MIXERCTL_H
#define OPENXT_MIXERCTL_H

int openxt_mixer_ctl_scontrols(void);
int openxt_mixer_ctl_scontents(void);
int openxt_mixer_ctl_sset(int argc, char *argv[]);
int openxt_mixer_ctl_sget(int argc, char *argv[]);

#endif // OPENXT_MIXERCTL_H
