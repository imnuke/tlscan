_BOOL8 __fastcall sub_406D11(__int64 a1, __int64 a2, __int64 a3, int a4, int a5, int a6)
{
  if ( nut_debug_level > 0 )
    s_upsdebugx(1, (unsigned int)"Trying to connect to UPS [%s]", *(_QWORD *)(a1 + 744), a4, a5, a6);
  sub_40376D(a1 + 792, 64);
  if ( dword_4117D4 == 1 )
    v19 = 2;
  else
    v19 = 1;
  if ( dword_4117F0 == 2 )
    v19 |= 4u;
  if ( dword_4117F0 == 10 )
    v19 |= 8u;
  if ( qword_4117B8 || dword_4117D0 != 1 )
  {
    if ( dword_4117D0 == 1 )
      v19 |= 0x10u;
    v14 = *(const char **)(a1 + 760);
    // NOTE: The upsmon calls upscli_connect with fourth argument v19.
    // NOTE: The bit 4 of v19 comes from the global variable dword_4117D0 (CERTVERIFY).
    if ( (int)upscli_connect((char **)a1, v14, *(_WORD *)(a1 + 768), v19) >= 0 )
    {
      sub_40374E(a1 + 792, 64);
      v18 = upscli_fd(a1);
      fcntl(v18, 2, 1);
      return (unsigned int)sub_403EEE(a1) == 1;
    }
    else
    {
      v15 = upscli_strerror(a1, v14);
      upslogx(3, (unsigned int)"UPS [%s]: connect failed: %s", *(_QWORD *)(a1 + 744), v15, v16, v17);
      sub_404422(a1);
      return 0;
    }
  }
  else
  {
    upslogx(3, (unsigned int)"Configuration error: CERTVERIFY is set, but CERTPATH isn't", v6, v7, v8, v9);
    upslogx(3, (unsigned int)"UPS [%s]: Connection impossible, dropping link", *(_QWORD *)(a1 + 744), v10, v11, v12);
    sub_404422(a1);
    sub_4052CA(a1);
    return 0;
  }
}

__int64 __fastcall sub_405EA1(unsigned __int64 a1, const char **a2)
{
  if ( a1 <= 1 )
    return 0;
  if ( !strcmp(*a2, "SHUTDOWNCMD") )
  {
    sub_405E1B(*a2, ptr, a2[1], (unsigned int)dword_4117A4);
    free(ptr);
    ptr = (char *)xstrdup(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "POWERDOWNFLAG") )
  {
    sub_405E1B(*a2, filename, a2[1], (unsigned int)dword_4117A4);
    free(filename);
    filename = (char *)xstrdup(a2[1]);
    if ( !dword_4117A4 )
      upslogx(6, (unsigned int)"Using power down flag file %s", (unsigned int)a2[1], v3, v4, v5);
    return 1;
  }
  else if ( !strcmp(*a2, "NOTIFYCMD") )
  {
    free(qword_411788);
    qword_411788 = (void *)xstrdup(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "POLLFREQ") )
  {
    v37 = atoi(a2[1]);
    if ( v37 >= 0 )
    {
      dword_41154C = v37;
    }
    else if ( nut_debug_level >= 0 )
    {
      s_upsdebugx(0, (unsigned int)"Ignoring invalid POLLFREQ value: %d", v37, v6, v7, v8);
    }
    return 1;
  }
  else if ( !strcmp(*a2, "POLLFREQALERT") )
  {
    v38 = atoi(a2[1]);
    if ( v38 >= 0 )
    {
      dword_411550 = v38;
    }
    else if ( nut_debug_level >= 0 )
    {
      s_upsdebugx(0, (unsigned int)"Ignoring invalid POLLFREQALERT value: %d", v38, v9, v10, v11);
    }
    return 1;
  }
  else if ( !strcmp(*a2, "HOSTSYNC") )
  {
    dword_411554 = atoi(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "DEADTIME") )
  {
    dword_411548 = atoi(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "MINSUPPLIES") )
  {
    v39 = atoi(a2[1]);
    if ( v39 >= 0 )
    {
      dword_411540 = v39;
    }
    else if ( nut_debug_level >= 0 )
    {
      s_upsdebugx(0, (unsigned int)"Ignoring invalid MINSUPPLIES value: %d", v39, v12, v13, v14);
    }
    return 1;
  }
  else if ( !strcmp(*a2, "RBWARNTIME") )
  {
    dword_411558 = atoi(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "NOCOMMWARNTIME") )
  {
    dword_41155C = atoi(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "FINALDELAY") )
  {
    v40 = atoi(a2[1]);
    if ( v40 >= 0 )
    {
      seconds = v40;
    }
    else if ( nut_debug_level >= 0 )
    {
      s_upsdebugx(0, (unsigned int)"Ignoring invalid FINALDELAY value: %d", v40, v15, v16, v17);
    }
    return 1;
  }
  else if ( !strcmp(*a2, "RUN_AS_USER") )
  {
    free(qword_4117B0);
    qword_4117B0 = (void *)xstrdup(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "CERTPATH") )
  {
    free(qword_4117B8);
    qword_4117B8 = (void *)xstrdup(a2[1]);
    return 1;
  }
  // NOTE: The global variable dword_4117D0 comes from the CERTVERIFY setting in config file.
  // NOTE: And we can see that the content comes from a2 of this function.
  else if ( !strcmp(*a2, "CERTVERIFY") )
  {
    dword_4117D0 = atoi(a2[1]);
    return 1;
  }
  else if ( !strcmp(*a2, "FORCESSL") )
  {
    dword_4117D4 = atoi(a2[1]);
    return 1;
  }
  else if ( !strcasecmp(*a2, "DEBUG_MIN") )
  {
    v36 = -1;
    if ( (unsigned int)str_to_int(a2[1], &v36, 10) && v36 >= 0 )
      dword_411568 = v36;
    else
      upslogx(
        6,
        (unsigned int)"WARNING : Invalid DEBUG_MIN value found in upsmon.conf global settings",
        v18,
        v19,
        v20,
        v21);
    return 1;
  }
  else if ( a1 > 2 )
  {
    if ( !strcmp(*a2, "NOTIFYMSG") )
    {
      sub_405B4D(a2[1], a2[2]);
      return 1;
    }
    else if ( !strcmp(*a2, "NOTIFYFLAG") )
    {
      sub_405C33(a2[1], a2[2]);
      return 1;
    }
    else if ( !strcmp(*a2, "CERTIDENT") )
    {
      free(qword_4117C0);
      qword_4117C0 = (void *)xstrdup(a2[1]);
      free(qword_4117C8);
      qword_4117C8 = (void *)xstrdup(a2[2]);
      return 1;
    }
    else if ( a1 > 4 )
    {
      if ( !strcmp(*a2, "CERTHOST") )
      {
        v22 = atoi(a2[4]);
        v23 = atoi(a2[3]);
        upscli_add_host_cert(a2[1], a2[2], v23, v22);
        return 1;
      }
      else if ( !strcmp(*a2, "MONITOR") )
      {
        if ( a1 == 5 )
        {
          upslogx(3, (unsigned int)"Unable to use old-style MONITOR line without a username", v24, v25, v26, v27);
          upslogx(
            3,
            (unsigned int)"Convert it and add a username to upsd.users - see the documentation",
            v28,
            v29,
            v30,
            v31);
          fatalx(1, (unsigned int)"Fatal error: unusable configuration", v32, v33, v34, v35, (char)a2);
        }
        sub_405731((unsigned int)dword_4117A4, a2[1], a2[2], a2[3], a2[4], a2[5]);
        return 1;
      }
      else
      {
        return 0;
      }
    }
    else
    {
      return 0;
    }
  }
  else
  {
    return 0;
  }
}

__int64 sub_4066B4()
{
  int v0; // ecx
  int v1; // r8d
  int v2; // r9d
  int v4; // r9d
  int v5; // ecx
  int v6; // r8d
  int v7; // r9d
  int v8; // ecx
  int v9; // r8d
  int v10; // r9d
  char s[512]; // [rsp+0h] [rbp-380h] BYREF
  _BYTE v12[16]; // [rsp+200h] [rbp-180h] BYREF
  const char **v13; // [rsp+210h] [rbp-170h]
  unsigned __int64 v14; // [rsp+220h] [rbp-160h]
  int v15; // [rsp+248h] [rbp-138h]
  _BYTE v16[300]; // [rsp+250h] [rbp-130h] BYREF
  unsigned int i; // [rsp+37Ch] [rbp-4h]

  pconf_init(v12, sub_406680);
  // NOTE: We can guess that qword_411798 is the config file path.
  if ( (unsigned int)pconf_file_begin(v12, qword_411798) )
  {
    if ( dword_4117A4 == 1 )
      dword_411568 = -1;
    while ( (unsigned int)pconf_file_next(v12) )
    {
      if ( (unsigned int)pconf_parse_error(v12) )
      {
        upslogx(3, (unsigned int)"Parse error: %s:%d: %s", (_DWORD)qword_411798, v15, (unsigned int)v16, v4);
      }
      // NOTE: The sub_4066B4 calls sub_405EA1 with the second argument from v13.
      // NOTE: And we can guess the pconf_file_begin handles the config file.
      else if ( v14 && !(unsigned int)sub_405EA1(v14, v13) )
      {
        snprintf(s, 0x200u, "%s line %d: invalid directive", qword_411798, v15);
        for ( i = 0; i < v14; ++i )
          snprintfcat((unsigned int)s, 512, (unsigned int)" %s", (unsigned int)v13[i], v6, v7, s[0]);
        upslogx(4, (unsigned int)"%s", (unsigned int)s, v5, v6, v7);
      }
    }
    if ( dword_4117A4 == 1 && dword_411568 >= 0 )
    {
      upslogx(6, (unsigned int)"Applying debug_min=%d from upsmon.conf", dword_411568, v8, v9, v10);
      nut_debug_level = dword_411568;
    }
    return pconf_finish(v12);
  }
  else
  {
    pconf_finish(v12);
    if ( dword_4117A4 != 1 )
      fatalx(1, (unsigned int)"%s", (unsigned int)v16, v0, v1, v2, s[0]);
    return upslog_with_errno(3, (unsigned int)"Reload failed: %s", (unsigned int)v16, v0, v1, v2, s[0]);
  }
}

void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  v22 = (const char *)xbasename(*a2, a2, a3);
  v29 = 0;
  v26 = 0;
  v25 = -1;
  v24 = -1;
  printf("Network UPS Tools %s %s\n", v22, UPS_VERSION);
  qword_411798 = (char *)xmalloc(512);
  v3 = (const char *)confpath();
  // NOTE: The global string qword_411798 is initialized to "<confpath>/upsmon.conf".
  // NOTE: So we can know the config file is named "upsmon.conf".
  snprintf(qword_411798, 0x200u, "%s/upsmon.conf", v3);
  v4 = strlen(qword_411798);
  qword_411798 = (char *)xrealloc(qword_411798, v4 + 1);
  qword_4117B0 = (void *)xstrdup("root");
  while ( 1 )
  {
    v21 = getopt(a1, a2, "+DFBhic:P:f:pu:VK46");
    if ( v21 == -1 )
      break;
    switch ( v21 )
    {
      case '4':
        dword_4117F0 = 2;
        break;
      case '6':
        dword_4117F0 = 10;
        break;
      case 'B':
        v25 = 0;
        break;
      case 'D':
        ++nut_debug_level;
        break;
      case 'F':
        v25 = 1;
        break;
      case 'K':
        v26 = 1;
        break;
      case 'P':
        v24 = parsepid(optarg);
        if ( v24 < 0 )
          sub_40748F(*a2);
        return;
      case 'V':
        exit(0);
      case 'c':
        v5 = strlen(optarg);
        if ( !strncmp(optarg, "fsd", v5) )
          v29 = 10;
        v6 = strlen(optarg);
        if ( !strncmp(optarg, "stop", v6) )
          v29 = 15;
        v7 = strlen(optarg);
        if ( !strncmp(optarg, "reload", v7) )
          v29 = 1;
        if ( !v29 )
          sub_40748F(*a2);
        return;
      case 'f':
        free(qword_411798);
        qword_411798 = (char *)xstrdup(optarg);
        break;
      case 'h':
        sub_40748F(*a2);
      case 'p':
        dword_411564 = 0;
        break;
      case 'u':
        free(qword_4117B0);
        qword_4117B0 = (void *)xstrdup(optarg);
        break;
      default:
        sub_40748F(*a2);
    }
  }
  if ( v25 < 0 )
    v25 = nut_debug_level > 0;
  if ( v29 )
  {
    if ( v24 >= 0 )
      v27 = sendsignalpid((unsigned int)v24, v29);
    else
      v27 = sendsignal(v22, v29);
    exit(v27 != 0);
  }
  if ( v24 >= 0 )
    v28 = sendsignalpid((unsigned int)v24, 0);
  else
    v28 = sendsignal(v22, 0);
  if ( v28 >= -3 )
  {
    if ( v28 <= -2 )
    {
      if ( v28 == -3 )
        v11 = "find";
      else
        v11 = "parse";
      upslogx(
        4,
        (unsigned int)"Could not %s PID file to see if previous upsmon instance is already running!\n",
        (_DWORD)v11,
        v8,
        v9,
        v10);
    }
    else if ( !v28 )
    {
      puts("Fatal error: A previous upsmon instance is already running!");
      puts("Either stop the previous instance first, or use the 'reload' command.");
      exit(1);
    }
  }
  open_syslog(v22);
  sub_4066B4();
  if ( dword_411568 > nut_debug_level )
    nut_debug_level = dword_411568;
  if ( nut_debug_level > 0 )
    s_upsdebugx(1, (unsigned int)"debug level is '%d'", nut_debug_level, v12, v13, v14);
  if ( v26 )
  {
    v15 = sub_4073F2();
    exit(v15);
  }
  if ( !ptr )
    puts("Warning: no shutdown command defined!");
  if ( filename )
    sub_40739A();
  v16 = dword_4117A0;
  if ( dword_4117A0 < (unsigned int)dword_411540 )
  {
    puts("\nFatal error: insufficient power configured!\n");
    printf("Sum of power values........: %d\n", dword_4117A0);
    printf("Minimum value (MINSUPPLIES): %d\n", dword_411540);
    puts("\nEdit your upsmon.conf and change the values.");
    exit(1);
  }
  if ( !v25 )
    background();
  if ( nut_debug_level > 0 )
    s_upsdebugx(1, (unsigned int)"debug level is '%d'", nut_debug_level, v12, v13, v14);
  if ( dword_411564 )
  {
    user_pwent = get_user_pwent(qword_4117B0);
    sub_40765C();
    writepid(v22);
    become_user(user_pwent);
  }
  else
  {
    upslogx(6, (unsigned int)"Warning: running as one big root process by request (upsmon -p)", v16, v12, v13, v14);
    writepid(v22);
  }
  if ( (int)upscli_init((unsigned int)dword_4117D0, qword_4117B8, qword_4117C0, qword_4117C8) < 0 )
    exit(1);
  sub_406AE4();
  closelog();
  open_syslog(v22);
  while ( !dword_4117A8 )
  {
    if ( dword_4117A4 )
      sub_40783A();
    for ( i = qword_4117E8; i; i = *(_QWORD *)(i + 840) )
      sub_4070FA(i);
    sub_404F33();
    if ( dword_411564 )
      sub_407951();
    waitpid(-1, 0, 1);
    sleep(dword_411544);
  }
  upslogx(6, (unsigned int)"Signal %d: exiting", dword_4117A8, v17, v18, v19);
  sub_4069B2();
  exit(0);
}