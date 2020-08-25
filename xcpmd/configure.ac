#
# Autoconf initialisation.
#
AC_INIT(xcpmd, 2.1)
AC_CONFIG_HEADERS(src/config.h)
AC_PREREQ(2.13)
AC_CONFIG_SRCDIR(src/xcpmd.c)
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall -Werror -Wno-portability])
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

#
# Libtool (xcpmd modules)
#
AM_PROG_AR
LT_INIT

# Check for libraries
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([yajl_tree_parse], [yajl])

# Required modules.
PKG_CHECK_MODULES([LIBPCI], [libpci])

PKG_CHECK_MODULES([LIBNL], [libnl-3.0])
PKG_CHECK_MODULES([LIBNL_GENL], [libnl-genl-3.0])

PKG_CHECK_MODULES([LIBEVENT], [libevent])

PKG_CHECK_MODULES([DBUS], [dbus-1])
PKG_CHECK_MODULES([GLIB], [glib-2.0])
PKG_CHECK_MODULES([DBUS_GLIB], [dbus-glib-1])

PKG_CHECK_MODULES([LIBXCDBUS], [libxcdbus])
PKG_CHECK_MODULES([LIBXCXENSTORE], [libxcxenstore])

#
# RPCGen
#
AC_ARG_WITH(idldir,
  AC_HELP_STRING([--with-idldir=PATH],[Path to dbus idl desription files]),
  IDLDIR=$with_idldir,
  IDLDIR=/usr/share/idl)
AC_SUBST(IDLDIR)

AC_ARG_WITH(rpcgen-templates,
  AC_HELP_STRING([--with-rpcgen-templates=PATH],[Path to xc-rpcgen template files]),
  RPCGEN_TEMPLATES=$with_rpcgen_templates,
  RPCGEN_TEMPLATES=)
AC_SUBST(RPCGEN_TEMPLATES)

AC_CHECK_PROG(XC_RPCGEN,xc-rpcgen,xc-rpcgen)


#
# Outputs.
#
AC_OUTPUT([Makefile
           src/Makefile])

