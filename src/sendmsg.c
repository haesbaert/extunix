/*  Copyright © 2012 Andre Nathan <andre@digirati.com.br>   */

/*
 * These functions are adapted from Stevens, Fenner and Rudoff, UNIX Network
 * Programming, Volume 1, Third Edition. We use CMSG_LEN instead of CMSG_SPACE
 * for the msg_controllen field of struct msghdr to avoid breaking LP64
 * systems (cf. Postfix source code).
 */

#define EXTUNIX_WANT_SENDMSG
#define EXTUNIX_WANT_IP_RECVIF
#define EXTUNIX_WANT_IP_RECVDSTADDR

#include "config.h"
#include <strings.h>

#if defined(EXTUNIX_HAVE_SENDMSG)

value my_alloc_sockaddr(struct sockaddr_storage *ss);
value int_to_recvflags(int);

CAMLprim value caml_extunix_sendmsg(value fd_val, value sendfd_val, value data_val)
{
  CAMLparam3(fd_val, sendfd_val, data_val);
  CAMLlocal1(data);
  size_t datalen;
  struct msghdr msg;
  struct iovec iov[1];
  int fd = Int_val(fd_val);
  ssize_t ret;
  char *buf;

  memset(&msg, 0, sizeof msg);

  if (sendfd_val != Val_none) {
    int sendfd = Int_val(Some_val(sendfd_val));
#if defined(CMSG_SPACE)
    union {
      struct cmsghdr cmsg; /* for alignment */
      char control[CMSG_SPACE(sizeof sendfd)];
    } control_un;
    struct cmsghdr *cmsgp;

    msg.msg_control = control_un.control;
    msg.msg_controllen = CMSG_LEN(sizeof sendfd);

    cmsgp = CMSG_FIRSTHDR(&msg);
    cmsgp->cmsg_len = CMSG_LEN(sizeof sendfd);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsgp) = sendfd;
#else
    msg.msg_accrights = (caddr_t)&sendfd;
    msg.msg_accrightslen = sizeof sendfd;
#endif
  }

  datalen = caml_string_length(data_val);
  buf = malloc(datalen);
  if (NULL == buf)
    uerror("sendmsg", Nothing);
  memcpy(buf, String_val(data_val), datalen);

  iov[0].iov_base = buf;
  iov[0].iov_len = datalen;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;

  caml_enter_blocking_section();
  ret = sendmsg(fd, &msg, 0);
  caml_leave_blocking_section();

  free(buf);

  if (ret == -1)
    uerror("sendmsg", Nothing);
  CAMLreturn (Val_unit);
}

CAMLprim value caml_extunix_recvmsg(value fd_val)
{
  CAMLparam1(fd_val);
  CAMLlocal2(data, res);
  struct msghdr msg;
  int fd = Int_val(fd_val);
  int recvfd;
  ssize_t len;
  struct iovec iov[1];
  char buf[4096];

#if defined(CMSG_SPACE)
  union {
    struct cmsghdr cmsg; /* just for alignment */
    char control[CMSG_SPACE(sizeof recvfd)];
  } control_un;
  struct cmsghdr *cmsgp;

  memset(&msg, 0, sizeof msg);
  msg.msg_control = control_un.control;
  msg.msg_controllen = CMSG_LEN(sizeof recvfd);
#else
  msg.msg_accrights = (caddr_t)&recvfd;
  msg.msg_accrightslen = sizeof recvfd;
#endif

  iov[0].iov_base = buf;
  iov[0].iov_len = sizeof buf;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;

  caml_enter_blocking_section();
  len = recvmsg(fd, &msg, 0);
  caml_leave_blocking_section();

  if (len == -1)
    uerror("recvmsg", Nothing);

  res = caml_alloc(2, 0);

#if defined(CMSG_SPACE)
  cmsgp = CMSG_FIRSTHDR(&msg);
  if (cmsgp == NULL) {
    Store_field(res, 0, Val_none);
  } else {
    CAMLlocal1(some_fd); 
    if (cmsgp->cmsg_len != CMSG_LEN(sizeof recvfd))
      unix_error(EINVAL, "recvmsg", caml_copy_string("wrong descriptor size"));
    if (cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS)
      unix_error(EINVAL, "recvmsg", caml_copy_string("invalid protocol"));
    some_fd = caml_alloc(1, 0);
    Store_field(some_fd, 0, Val_int(*(int *)CMSG_DATA(cmsgp)));
    Store_field(res, 0, some_fd);
  }
#else
  if (msg.msg_accrightslen != sizeof recvfd) {
    Store_field(res, 0, Val_none);
  } else {
    CAMLlocal1(some_fd);
    some_fd = caml_alloc(1, 0);
    Store_field(some_fd, 0, Val_int(recvfd));
    Store_field(res, 0, some_fd);
  }
#endif

  data = caml_alloc_string(len);
  memcpy(String_val(data), buf, len);
  Store_field(res, 1, data);

  CAMLreturn (res);
}

enum {
  TAG_FILEDESCRIPTOR,
  TAG_IP_RECVIF,
  TAG_IP_RECVDSTADDR
};

/* From caml, sadly, it's a static in sendrecv.c */
static int msg_flag_table[] = {
  MSG_OOB, MSG_DONTROUTE, MSG_PEEK
};

CAMLprim value caml_extunix_recvmsg2(value vfd, value vbuf, value ofs, value vlen,
  value vflags)
{
  CAMLparam4(vfd, vbuf, ofs, vlen);
  CAMLlocal5(vres, vlist, v, vx, vsaddr);
  union {
    struct cmsghdr hdr;
    char buf[CMSG_SPACE(sizeof(int)) /* File descriptor passing */
#ifdef EXTUNIX_HAVE_IP_RECVIF
        + CMSG_SPACE(sizeof(struct sockaddr_dl)) /* IP_RECVIF */
#endif
#ifdef EXTUNIX_HAVE_IP_RECVDSTADDR
        + CMSG_SPACE(sizeof(struct in_addr))     /* IP_RECVDSTADDR */
#endif
    ];
  } cmsgbuf;
  struct iovec             iov;
  struct msghdr            msg;
  struct cmsghdr          *cmsg;
  ssize_t                  n;
  size_t                   len;
  char                     iobuf[UNIX_BUFFER_SIZE];
  struct sockaddr_storage  ss;
  int                      sendflags;
#ifdef EXTUNIX_HAVE_IP_RECVIF
  struct sockaddr_dl      *dst = NULL;
#endif

  len = Long_val(vlen);

  memset(&iov, 0, sizeof(iov));
  memset(&msg, 0, sizeof(msg));

  if (len > UNIX_BUFFER_SIZE)
    len = UNIX_BUFFER_SIZE;

  iov.iov_base = iobuf;
  iov.iov_len = len;
  msg.msg_name = &ss;
  msg.msg_namelen = sizeof(ss);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = &cmsgbuf.buf;
  msg.msg_controllen = sizeof(cmsgbuf.buf);
  sendflags = caml_convert_flag_list(vflags, msg_flag_table);

  caml_enter_blocking_section();
  n = recvmsg(Int_val(vfd), &msg, sendflags);
  caml_leave_blocking_section();

  vres = caml_alloc_small(4, 0);

  if (n == -1) {
    uerror("recvmsg", Nothing);
    CAMLreturn (vres);
  }

  vsaddr = my_alloc_sockaddr(&ss);

  memmove(&Byte(vbuf, Long_val(ofs)), iobuf, n);

  vlist = Val_int(0);

  /* Build the variant list vlist */
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS) {
      /* CMSG_DATA is aligned, so the following is cool */
      v = caml_alloc_small(2, TAG_FILEDESCRIPTOR);
      Field(v, 0) = Val_int(*(int *)CMSG_DATA(cmsg));
      Field(v, 1) = vlist;
      vlist = v;
      continue;
    }

#ifdef EXTUNIX_HAVE_IP_RECVIF
    if (cmsg->cmsg_level == IPPROTO_IP &&
        cmsg->cmsg_type == IP_RECVIF) {
      dst = (struct sockaddr_dl *)CMSG_DATA(cmsg);
      v = caml_alloc_small(2, 0);
      vx = caml_alloc_small(1, TAG_IP_RECVIF);
      Field(vx, 0) = Val_int(dst->sdl_index);
      Field(v, 0) = vx;
      Field(v, 1) = vlist;
      vlist = v;
      continue;
    }
#endif
#ifdef EXTUNIX_HAVE_IP_RECVDSTADDR
    if (cmsg->cmsg_level == IPPROTO_IP &&
        cmsg->cmsg_type == IP_RECVDSTADDR) {
      struct in_addr ipdst;
      ipdst = *(struct in_addr *)CMSG_DATA(cmsg);
      v = caml_alloc_small(2, 0);
      vx = caml_alloc_small(1, TAG_IP_RECVDSTADDR);
      Field(vx, 0) = caml_alloc_string(4);
      memcpy(String_val(Field(vx, 0)), &ipdst, 4);
      Field(v, 0) = vx;
      Field(v, 1) = vlist;
      vlist = v;
      continue;
    }
#endif
  }

  /* Now build the result */
  Field(vres, 0) = Val_long(n);
  Field(vres, 1) = vsaddr;
  Field(vres, 2) = vlist;
  Field(vres, 3) = int_to_recvflags(msg.msg_flags);

  CAMLreturn(vres);
}

value my_alloc_sockaddr(struct sockaddr_storage *ss)
{
  value res, a;
  struct sockaddr_un *sun;
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  switch(ss->ss_family) {
  case AF_UNIX:
    sun = (struct sockaddr_un *) ss;
    a = caml_copy_string(sun->sun_path);
    Begin_root (a);
    res = caml_alloc_small(1, 0);
    Field(res,0) = a;
    End_roots();
    break;
  case AF_INET:
    sin = (struct sockaddr_in *) ss;
    a = caml_alloc_string(4);
    memcpy(String_val(a), &sin->sin_addr, 4);
    Begin_root (a);
    res = caml_alloc_small(2, 1);
    Field(res, 0) = a;
    Field(res, 1) = Val_int(ntohs(sin->sin_port));
    End_roots();
    break;
  case AF_INET6:
    sin6 = (struct sockaddr_in6 *) ss;
    a = caml_alloc_string(16);
    memcpy(String_val(a), &sin6->sin6_addr, 16);
    Begin_root (a);
    res = caml_alloc_small(2, 1);
    Field(res, 0) = a;
    Field(res, 1) = Val_int(ntohs(sin6->sin6_port));
    End_roots();
    break;
  default:
    unix_error(EAFNOSUPPORT, "", Nothing);
  }

  return res;
}

enum {
  TAG_MSG_OOB,
  TAG_MSG_EOR,
  TAG_MSG_TRUNC,
  TAG_MSG_CTRUNC
#if 0
  TAG_MSG_BCAST,
  TAG_MSG_MCAST,
#endif
};

static struct {
  int flag;
  int tag;
} recv_flags[] = {
  { MSG_OOB,    TAG_MSG_OOB },
  { MSG_EOR,    TAG_MSG_EOR },
  { MSG_TRUNC,  TAG_MSG_TRUNC },
  { MSG_CTRUNC, TAG_MSG_CTRUNC },
#if 0
  { MSG_BCAST,  TAG_MSG_BCAST },
  { MSG_MCAST,  TAG_MSG_MCAST },
#endif
  { 0,  0 }
};

value int_to_recvflags(int flags)
{
  value list = Val_int(0);
  value v;
  int i, flag, tag;

  for (i = 0; ;i++) {
    flag = recv_flags[i].flag;
    tag = recv_flags[i].tag;

    if (!flag)
      break;

    if ((flags & flag) == 0)
      continue;

    v = caml_alloc_small(2, 0);
    Field(v, 0) = Val_int(tag);
    Field(v, 1) = list;
    list = v;
  }

  return (list);
}

#endif /* EXTUNIX_HAVE_SENDMSG */
