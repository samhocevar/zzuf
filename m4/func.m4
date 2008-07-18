dnl  Check for the __func__ keyword
AC_DEFUN([AC_C_FUNC],
 [AC_MSG_CHECKING(for __func__)
  ac_v_func='"unknown"'
  AC_TRY_COMPILE([], [char const *f = __func__;],
   [ac_v_func="__func__"],
   [AC_TRY_COMPILE([], [char const *f = __FUNCTION__;],
     [ac_v_func="__FUNCTION__"])])
  if test "$ac_v_func" != "__func__"; then
    AC_DEFINE_UNQUOTED(__func__, $ac_v_func, [Define to a way to access function names])
  fi
  AC_MSG_RESULT($ac_v_func)])

