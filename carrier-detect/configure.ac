#
# Autoconf initialisation.
#
AC_INIT(carrier-detect, 1.0)
AC_PREREQ(2.13)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])

#
# Version management.
# +1    : 0     Interface changes breaking retro-compatibility.
# 0     : +1    Internal changes without lost of retro-compatibility.
#
VERSION_MAJOR=0
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
AM_PROG_AR

# Compiler capabilities.
AC_C_INLINE
AC_C_CONST

# Required headers.
AC_CHECK_HEADERS([sys/mman.h stdio.h])

# Required packages.
PKG_CHECK_MODULES(LIBNL, [libnl-3.0])
PKG_CHECK_MODULES(LIBNL_ROUTE, [libnl-route-3.0])

# Output files.
AC_OUTPUT([Makefile])
