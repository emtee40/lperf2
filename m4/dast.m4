
AH_TEMPLATE([HAVE_POSIX_THREAD], [])
AH_TEMPLATE([_REENTRANT], [])
AH_TEMPLATE([ssize_t], [Define to "int" if <sys/types.h> does not define.])

dnl ===================================================================
dnl DAST_REPLACE_TYPE( type, sizeof )
dnl Check for the type as AC_CHECK_TYPE does. Define HAVE_<type>
dnl if type exists; don't define <type> to anything if it doesn't exist.
dnl Useful if there is no well-defined default type, such as int32_t

AC_DEFUN([DAST_REPLACE_TYPE], [

AC_CACHE_CHECK(for $1, ac_cv_type_$1,
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[$ac_includes_default]],
    [[$1 foo]])],
  ac_cv_type_$1=yes,
  ac_cv_type_$1=no)

if test $ac_cv_type_$1 != yes ; then
  if test "$ac_cv_sizeof_char" = $2; then
    ac_cv_type_$1="char"
  elif test "$ac_cv_sizeof_short" = $2; then
    ac_cv_type_$1="short"
  elif test "$ac_cv_sizeof_int" = $2; then
    ac_cv_type_$1="int"
  elif test "$ac_cv_sizeof_long" = $2; then
    ac_cv_type_$1="long"
  elif test "$ac_cv_sizeof_long_long" = $2; then
    ac_cv_type_$1="long long"
  fi
fi)

if test "$ac_cv_type_$1" != no; then
  if test "$ac_cv_type_$1" != yes; then
    AC_DEFINE_UNQUOTED($1, $ac_cv_type_$1)
  fi
  AC_DEFINE_UNQUOTED(HAVE_`echo $1 | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`)
fi

])

AC_DEFUN([DAST_REPLACE_TYPE_UNSIGNED], [

AC_CACHE_CHECK(for $1, ac_cv_type_$1,
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[$ac_includes_default]],
    [[$1 foo]])],
  ac_cv_type_$1=yes,
  ac_cv_type_$1=no)

if test $ac_cv_type_$1 != yes ; then
  if test "$ac_cv_sizeof_unsigned_char" = $2; then
    ac_cv_type_$1="unsigned char"
  elif test "$ac_cv_sizeof_unsigned_short" = $2; then
    ac_cv_type_$1="unsigned short"
  elif test "$ac_cv_sizeof_unsigned_int" = $2; then
    ac_cv_type_$1="unsigned int"
  elif test "$ac_cv_sizeof_unsigned_long" = $2; then
    ac_cv_type_$1="unsigned long"
  elif test "$ac_cv_sizeof_unsigned_long_long" = $2; then
    ac_cv_type_$1="unsigned long long"
  fi
fi)

if test "$ac_cv_type_$1" != no; then
  if test "$ac_cv_type_$1" != yes; then
    AC_DEFINE_UNQUOTED($1, $ac_cv_type_$1)
  fi
  AC_DEFINE_UNQUOTED(HAVE_`echo $1 | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`)
fi

])

dnl DAST_CHECK_ARG
dnl Check for the 3rd arguement to accept

AC_DEFUN([DAST_ACCEPT_ARG], [
  if test -z "$ac_cv_accept_arg" ; then
    AC_LANG_PUSH([C++])

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
      [[$ac_includes_default
       #include <sys/socket.h>]],
      [[$1 length;
       accept( 0, 0, &length );]])],
    ac_cv_accept_arg=$1)

    AC_LANG_POP([C++])
  fi
])
