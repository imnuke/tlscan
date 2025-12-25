void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  v26 = 0;
  v25 = 0;
  v24 = 0;
  v23 = xbasename(*a2, a2, a3);
  while ( 1 )
  {
    v22 = getopt(a1, a2, "+hlLcV");
    if ( v22 == -1 )
    {
      argc = a1 - optind;
      argv = &a2[optind];
      sub_404910(sub_402A68);
      if ( v26 )
      {
        if ( *argv )
          v6 = *argv;
        else
          v6 = "localhost";
        if ( (unsigned int)upscli_splitaddr(v6, &qword_408430, &v21) )
          fatalx(
            1,
            (unsigned int)"Error: invalid hostname.\nRequired format: [hostname[:port]]",
            v7,
            v8,
            v9,
            v10,
            (char)argv);
      }
      else if ( (unsigned int)upscli_splitname(*argv, &ptr, &qword_408430, &v21) )
      {
        fatalx(
          1,
          (unsigned int)"Error: invalid UPS definition.\nRequired format: upsname[@hostname[:port]]",
          v11,
          v12,
          v13,
          v14,
          (char)argv);
      }
      qword_408438 = (void *)xmalloc(744);
      // NOTE: The upsc calls upscli_connect with fourth argument 1 (SSL required).
      // NOTE: Since the bit 4 is not set, the upscli_tryconnect will not verify the server certificate.
      // NOTE: This should be reported as a vulnerability.
      if ( (int)upscli_connect(qword_408438, qword_408430, v21, 1) < 0 )
      {
        v15 = upscli_strerror(qword_408438);
        fatalx(1, (unsigned int)"Error: %s", v15, v16, v17, v18, (char)argv);
      }
      if ( v26 )
      {
        sub_402843(v24);
        exit(0);
      }
      if ( v25 )
      {
        sub_402969(ptr);
        exit(0);
      }
      if ( argc <= 1 )
        sub_402734();
      else
        sub_402620(argv[1]);
      exit(0);
    }
    if ( v22 == 86 )
      fatalx(0, (unsigned int)"Network UPS Tools upscmd %s", (_DWORD)UPS_VERSION, v3, v4, v5, (char)a2);
    if ( v22 <= 86 )
      break;
    if ( v22 == 99 )
    {
      v25 = 1;
    }
    else
    {
      if ( v22 != 108 )
      {
LABEL_13:
        sub_40253E(v23);
        exit(0);
      }
LABEL_10:
      v26 = 1;
    }
  }
  if ( v22 != 76 )
    goto LABEL_13;
  v24 = 1;
  goto LABEL_10;
}