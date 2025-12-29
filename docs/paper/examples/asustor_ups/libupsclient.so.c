__int64 __fastcall upscli_sslinit(__int64 a1, int a2, int a3, int a4, int a5, int a6)
{
  if ( !upscli_initialized )
  {
    if ( nut_debug_level > 2 )
      s_upsdebugx(
        3,
        (unsigned int)"upscli not initialized, force initialisation without SSL configuration",
        a3,
        a4,
        a5,
        a6);
    upscli_init(0, 0, 0, 0);
  }
  strcpy(s, "STARTTLS\n");
  v6 = strlen(s);
  if ( upscli_sendline(a1, s, v6) )
    return 0xFFFFFFFFLL;
  if ( upscli_readline(a1, s, 512) )
    return 0xFFFFFFFFLL;
  if ( strncmp(s, "OK STARTTLS", 0xBu) )
    return 0;
  if ( ssl_ctx )
  {
    v12 = SSL_new(ssl_ctx);
    *(_QWORD *)(a1 + 656) = v12;
    if ( *(_QWORD *)(a1 + 656) )
    {
      if ( (unsigned int)SSL_set_fd(*(_QWORD *)(a1 + 656), *(unsigned int *)(a1 + 12)) == 1 )
      {
        // NOTE: Whether to verify the server certificate or not is controlled by 'a2'.
        if ( a2 )
          SSL_set_verify(*(_QWORD *)(a1 + 656), 1, 0);
        else
          SSL_set_verify(*(_QWORD *)(a1 + 656), 0, 0);
        // NOTE: Vulnerability: The code does not check the hostname before proceeding.
        v20 = SSL_connect(*(_QWORD *)(a1 + 656));
        v30 = v20;
        if ( v20 )
        {
          if ( v20 == 1 )
          {
            if ( nut_debug_level > 2 )
            {
              version = SSL_get_version(*(_QWORD *)(a1 + 656));
              s_upsdebugx(3, (unsigned int)"SSL connected (%s)", version, v26, v27, v28);
            }
            return 1;
          }
          else
          {
            upslog_with_errno(1, (unsigned int)"Unknown return value from SSL_connect %d", v30, v22, v23, v24);
            ssl_error(*(_QWORD *)(a1 + 656), v30);
            return 0xFFFFFFFFLL;
          }
        }
        else
        {
          upslog_with_errno(1, (unsigned int)"SSL_connect do not accept handshake.", v21, v22, v23, v24);
          ssl_error(*(_QWORD *)(a1 + 656), v30);
          return 0xFFFFFFFFLL;
        }
      }
      else
      {
        if ( nut_debug_level > 2 )
          s_upsdebugx(3, (unsigned int)"Can not bind file descriptor to SSL socket", v16, v17, v18, v19);
        return 0xFFFFFFFFLL;
      }
    }
    else
    {
      if ( nut_debug_level > 2 )
        s_upsdebugx(3, (unsigned int)"Can not create SSL socket", v12, v13, v14, v15);
      return 0;
    }
  }
  else
  {
    if ( nut_debug_level > 2 )
      s_upsdebugx(3, (unsigned int)"SSL context is not available", v8, v9, v10, v11);
    return 0;
  }
}

__int64 __fastcall upscli_tryconnect(char **a1, const char *a2, unsigned __int16 a3, int a4, struct timeval *a5)
{
  if ( !a1 )
    return 0xFFFFFFFFLL;
  memset(a1, 0, 0x2E8u);
  *((_DWORD *)a1 + 7) = 429392648;
  *((_DWORD *)a1 + 3) = -1;
  if ( !a2 )
  {
    *((_DWORD *)a1 + 5) = 2;
    return 0xFFFFFFFFLL;
  }
  snprintf(service, 0x20u, "%ju", a3);
  memset(&req, 0, sizeof(req));
  if ( (a4 & 8) != 0 )
  {
    req.ai_family = 10;
  }
  else if ( (a4 & 4) != 0 )
  {
    req.ai_family = 2;
  }
  else
  {
    req.ai_family = 0;
  }
  req.ai_socktype = 1;
  req.ai_protocol = 6;
  while ( 1 )
  {
    v36 = getaddrinfo(a2, service, &req, &pai);
    if ( !v36 )
      break;
    if ( v36 == -10 )
    {
      *((_DWORD *)a1 + 5) = 40;
      return 0xFFFFFFFFLL;
    }
    if ( v36 <= -10 )
    {
      if ( v36 == -11 )
        *((_DWORD *)a1 + 6) = *__errno_location();
LABEL_20:
      *((_DWORD *)a1 + 5) = 0;
      return 0xFFFFFFFFLL;
    }
    if ( v36 != -3 )
    {
      if ( v36 == -2 )
      {
        *((_DWORD *)a1 + 5) = 2;
        return 0xFFFFFFFFLL;
      }
      goto LABEL_20;
    }
  }
  for ( i = pai; i; i = i->ai_next )
  {
    fd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
    if ( fd >= 0 )
    {
      if ( a5 )
      {
        v32 = fcntl(fd, 3) | 0x800LL;
        fcntl(fd, 4, v32);
      }
      while ( 1 )
      {
        v36 = connect(fd, i->ai_addr, i->ai_addrlen);
        if ( v36 >= 0 )
          break;
        if ( *__errno_location() == 115 )
        {
          memset(&writefds, 0, sizeof(writefds));
          v31 = 0;
          v30 = (unsigned int)service;
          writefds.fds_bits[fd / 64] |= 1LL << (fd % 64);
          select(fd + 1, 0, &writefds, 0, a5);
          if ( (writefds.fds_bits[fd / 64] & (1LL << (fd % 64))) == 0 )
          {
            v36 = -1;
            break;
          }
          optlen = 4;
          getsockopt(fd, 1, 4, &optval, &optlen);
          if ( !optval )
          {
            v36 = 0;
            break;
          }
          *__errno_location() = optval;
        }
        v7 = *__errno_location();
        if ( v7 != 11 )
        {
          if ( v7 == 97 )
            break;
          if ( v7 != 4 )
          {
            *((_DWORD *)a1 + 5) = 31;
            *((_DWORD *)a1 + 6) = *__errno_location();
            break;
          }
        }
      }
      if ( v36 >= 0 )
      {
        if ( a5 )
        {
          v32 = fcntl(fd, 3) & 0xFFFFFFFFFFFFF7FFLL;
          fcntl(fd, 4, v32);
        }
        *((_DWORD *)a1 + 3) = fd;
        *((_DWORD *)a1 + 5) = 0;
        *((_DWORD *)a1 + 6) = 0;
        break;
      }
      close(fd);
    }
    else
    {
      v6 = *__errno_location();
      if ( v6 != 22 && v6 != 97 )
      {
        *((_DWORD *)a1 + 5) = 29;
        *((_DWORD *)a1 + 6) = *__errno_location();
      }
    }
  }
  freeaddrinfo(pai);
  if ( *((int *)a1 + 3) < 0 )
    return 0xFFFFFFFFLL;
  pconf_init(a1 + 4, 0);
  *a1 = strdup(a2);
  if ( !*a1 )
  {
    *((_DWORD *)a1 + 5) = 40;
    upscli_disconnect(a1);
    return 0xFFFFFFFFLL;
  }
  *((_WORD *)a1 + 4) = a3;
  host_cert = upscli_find_host_cert();
  if ( host_cert )
  {
    v35 = *(_DWORD *)(host_cert + 16);
    v34 = *(_DWORD *)(host_cert + 20);
  }
  else
  {
    v35 = (a4 >> 4) & 1;
    v34 = (a4 >> 1) & 1;
  }
  v28 = a4 & 1; // SSL flags from parameter a4: bit 0 = SSL required, bit 1 = verify certificate, bit 4 = force certificate verification
  if ( (a4 & 1) != 0 || v34 )
  {
    // NOTE: The upscli_tryconnect calls the upscli_sslinit. The second argument comes from v35, which is derived from host certificate or from parameter a4 bit 4.
    // NOTE: But the upscli_find_host_cert is a stub function that always returns NULL in this code base, so v35 is always derived from a4 bit 4.
    v27 = upscli_sslinit((__int64)a1, v35, v35, v8, v9, v10);
    if ( v34 && v27 != 1 )
    {
      upslogx(3, (unsigned int)"Can not connect to NUT server %s in SSL, disconnect", (_DWORD)a2, v11, v12, v13);
      *((_DWORD *)a1 + 5) = 36;
      upscli_disconnect(a1);
      return 0xFFFFFFFFLL;
    }
    if ( v28 && v27 == -1 )
    {
      upslogx(5, (unsigned int)"Error while connecting to NUT server %s, disconnect", (_DWORD)a2, v11, v12, v13);
      upscli_disconnect(a1);
      return 0xFFFFFFFFLL;
    }
    if ( !v28 || v27 )
    {
      upslogx(6, (unsigned int)"Connected to NUT server %s in SSL", (_DWORD)a2, v11, v12, v13, a5);
      if ( !v35 )
        upslogx(4, (unsigned int)"Certificate verification is disabled", v14, v15, v16, v17);
    }
    else
    {
      if ( v35 )
      {
        upslogx(
          5,
          (unsigned int)"Can not connect to NUT server %s in SSL and certificate is needed, disconnect",
          (_DWORD)a2,
          v11,
          v12,
          v13);
        upscli_disconnect(a1);
        return 0xFFFFFFFFLL;
      }
      if ( nut_debug_level > 2 )
        s_upsdebugx(
          3,
          (unsigned int)"Can not connect to NUT server %s in SSL, continue unencrypted",
          (_DWORD)a2,
          v11,
          v12,
          v13);
    }
  }
  return 0;
}

// NOTE: The upscli_connect is an exported function.
// NOTE: It's called by both upsc and upsmon.
__int64 __fastcall upscli_connect(char **a1, const char *a2, unsigned __int16 a3, int a4)
{
  // NOTE: The upscli_tryconnect is called by upscli_connect.
  // NOTE: The fourth argument to upscli_tryconnect is 'a4' from upscli_connect.
  // NOTE: So when the bit 4 of 'a4' from upscli_connect is set, the upscli_tryconnect will force certificate verification.
  // NOTE: Else the upscli_tryconnect will not verify the server certificate.
  return upscli_tryconnect(a1, a2, a3, a4, 0);
}