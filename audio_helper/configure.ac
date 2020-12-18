#
# Autoconf initialisation.
#
AC_INIT(audio-helper, 2.1)
AC_CONFIG_HEADERS(src/config.h)
AC_PREREQ(2.13)
AC_CONFIG_SRCDIR(src/main.c)
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall -Werror])
AC_CONFIG_MACRO_DIRS([m4])

#
# Version management.
# +1    : 0     Interface changes breaking retro-compatibility.
# 0     : +1    Internal changes without lost of retro-compatibility.
#
VERSION_MAJOR=2
VERSION_MINOR=1
AC_DEFINE_UNQUOTED([VERSION_MAJOR], [$VERSION_MAJOR], [major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [$VERSION_MINOR], [minor version number])

#
# Standard checks.
#
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Compiler capabilities.
AC_C_INLINE
AC_C_CONST

# Check for libraries.
AC_SEARCH_LIBS([sqrt], [m])

# Required modules.
PKG_CHECK_MODULES([LIBARGO], [libargo])
PKG_CHECK_MODULES([ALSA], [alsa])

#
# Outputs.
#
AC_OUTPUT([Makefile
           src/Makefile])

