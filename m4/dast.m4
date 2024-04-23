
AH_TEMPLATE([HAVE_POSIX_THREAD], [])
AH_TEMPLATE([_REENTRANT], [])
AH_TEMPLATE([ssize_t], [Define to "int" if <sys/types.h> does not define.])

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
