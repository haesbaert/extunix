
#define EXTUNIX_WANT_SOCKOPT
#include "config.h"

#if defined(EXTUNIX_HAVE_SOCKOPT)

#include <caml/fail.h>

#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT -1
#endif

#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE -1
#endif

#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL -1
#endif

static int tcp_options[] = { 
  TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL,
};

CAMLprim value caml_extunix_setsockopt_int(value fd, value k, value v)
{
  int optval = Int_val(v);
  socklen_t optlen = sizeof(optval);

  if (Int_val(k) < 0 || (unsigned int)Int_val(k) >= sizeof(tcp_options) / sizeof(tcp_options[0]))
    caml_invalid_argument("setsockopt_int");

  if (tcp_options[Int_val(k)] == -1) {
    caml_raise_not_found();
    return Val_unit;
  }

  if (0 != setsockopt(Int_val(fd), IPPROTO_TCP, tcp_options[Int_val(k)], &optval, optlen))
    uerror("setsockopt_int", Nothing);

  return (Val_unit);
}

CAMLprim value caml_extunix_getsockopt_int(value fd, value k)
{
  int optval;
  socklen_t optlen = sizeof(optval);

  if (Int_val(k) < 0 || (unsigned int)Int_val(k) >= sizeof(tcp_options) / sizeof(tcp_options[0]))
    caml_invalid_argument("getsockopt_int");

  if (tcp_options[Int_val(k)] == -1) {
    caml_raise_not_found();
    return Val_unit;
  }

  if (0 != getsockopt(Int_val(fd), IPPROTO_TCP, tcp_options[Int_val(k)], &optval, &optlen))
    uerror("getsockopt_int", Nothing);

  return Val_int(optval);
}

#ifndef EXTUNIX_HAVE_IP_RECVIF
#define IP_RECVIF -1
#endif

#ifndef EXTUNIX_HAVE_IP_RECVDSTADDR
#define IP_RECVDSTADDR -1
#endif

static int ip_options[] = {
  IP_RECVIF,
  IP_RECVDSTADDR
};

CAMLprim value caml_extunix_setsockopt_bool(value fd, value k, value v)
{
  int optval = Bool_val(v);
  socklen_t optlen = sizeof(optval);

  if (Int_val(k) < 0 || (unsigned int)Int_val(k) >=
      sizeof(ip_options) / sizeof(ip_options[0]))
    caml_invalid_argument("setsockopt_int");

  if (ip_options[Int_val(k)] == -1) {
    errno = ENOPROTOOPT;
    uerror("setsockopt_bool", Nothing);
    return Val_unit;
  }

  if (setsockopt(Int_val(fd), IPPROTO_IP,
      ip_options[Int_val(k)], &optval, optlen) != 0)
    uerror("setsockopt_bool", Nothing);

  return Val_unit;
}

CAMLprim value caml_extunix_getsockopt_bool(value fd, value k)
{
  int optval;
  socklen_t optlen = sizeof(optval);

  if (Int_val(k) < 0 ||
      (unsigned int)Int_val(k) >= sizeof(ip_options) / sizeof(ip_options[0]))
    caml_invalid_argument("getsockopt_int");

  if (ip_options[Int_val(k)] == -1) {
    errno = ENOPROTOOPT;
    uerror("setsockopt_bool", Nothing);
    return Val_unit;
  }

  if (getsockopt(Int_val(fd), IPPROTO_TCP,
      ip_options[Int_val(k)], &optval, &optlen) != 0)
    uerror("getsockopt_int", Nothing);

  return Val_bool(optval);
}

#endif
