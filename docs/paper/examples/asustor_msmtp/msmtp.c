__int64 __fastcall sub_40675F(__int64 a1, __int64 a2, _QWORD *a3, _DWORD *a4, __int64 *a5)
{
  // NOTE: The config file is named msmtprc.
  conffile = "/.../.../msmtprc";
  for (line = 1; ; line++) {
    fgets(linebuf, sizeof(linebuf), a3);
  }

  for ( i = 1; ; ++i )
  {
    v90 = sub_4063C6(a2, &s1, &s, &v79, &v78, a5);
    if ( v90 )
      break;
    if ( !v79 )
    {
      if ( v78 )
        break;
      if ( !v88 && strcmp(s1, "account") && strcmp(s1, "defaults") )
      {
        v88 = sub_403C83(v84);
        v5 = sub_4166C4("default");
        *(_QWORD *)v88 = v5;
        v6 = sub_4166C4(a1);
        *(_QWORD *)(v88 + 8) = v6;
        *(_QWORD *)(v88 + 16) = 0;
        sub_408A49(v89, v88);
        v89 = *(_QWORD *)(v89 + 8);
      }

      // Non-related lines omitted...

      else if ( !strcmp(s1, "tls_key_file") )
      {
        *(_QWORD *)(v88 + 16) |= 0x20000uLL;
        free(*(void **)(v88 + 144));
        if ( *s )
        {
          v46 = sub_415CF8(s);
          *(_QWORD *)(v88 + 144) = v46;
        }
        else
        {
          *(_QWORD *)(v88 + 144) = 0;
        }
      }
      else if ( !strcmp(s1, "tls_cert_file") )
      {
        *(_QWORD *)(v88 + 16) |= 0x40000uLL;
        free(*(void **)(v88 + 152));
        if ( *s )
        {
          v47 = sub_415CF8(s);
          *(_QWORD *)(v88 + 152) = v47;
        }
        else
        {
          *(_QWORD *)(v88 + 152) = 0;
        }
      }
      else if ( !strcmp(s1, "tls_trust_file") )
      {
        *(_QWORD *)(v88 + 16) |= 0x80000uLL;
        free(*(void **)(v88 + 160));
        if ( *s )
        {
          v48 = sub_415CF8(s);
          *(_QWORD *)(v88 + 160) = v48;
        }
        else
        {
          *(_QWORD *)(v88 + 160) = 0;
        }
      }
      else if ( !strcmp(s1, "tls_crl_file") )
      {
        *(_QWORD *)(v88 + 16) |= 0x100000uLL;
        free(*(void **)(v88 + 168));
        if ( *s )
        {
          v49 = sub_415CF8(s);
          *(_QWORD *)(v88 + 168) = v49;
        }
        else
        {
          *(_QWORD *)(v88 + 168) = 0;
        }
      }
      else if ( !strcmp(s1, "tls_fingerprint") )
      {
        *(_QWORD *)(v88 + 16) |= 0x200000uLL;
        free(*(void **)(v88 + 176));
        *(_QWORD *)(v88 + 176) = 0;
        free(*(void **)(v88 + 184));
        *(_QWORD *)(v88 + 184) = 0;
        free(*(void **)(v88 + 192));
        *(_QWORD *)(v88 + 192) = 0;
        if ( *s )
        {
          if ( strlen(s) == 95 )
          {
            v50 = sub_404817(s, 32);
            *(_QWORD *)(v88 + 176) = v50;
          }
          else if ( strlen(s) == 59 )
          {
            v51 = sub_404817(s, 20);
            *(_QWORD *)(v88 + 184) = v51;
          }
          else if ( strlen(s) == 47 )
          {
            v52 = sub_404817(s, 16);
            *(_QWORD *)(v88 + 192) = v52;
          }
          if ( !*(_QWORD *)(v88 + 176) && !*(_QWORD *)(v88 + 184) && !*(_QWORD *)(v88 + 192) )
            goto LABEL_195;
        }
      }
      // NOTE: Load the tls_certcheck option from config file into "*(_DWORD *)(v88 + 204)".
      // NOTE: Actually the "*(_DWORD *)(v88 + 204)" is mtls->no_certcheck.
      else if ( !strcmp(s1, "tls_certcheck") )
      {
        *(_QWORD *)(v88 + 16) |= 0x400000uLL;
        if ( *s && !(unsigned int)sub_404715(s) )
        {
          if ( !(unsigned int)sub_40473C(s) )
            goto LABEL_195;
          *(_DWORD *)(v88 + 204) = 1;
        }
        else
        {
          *(_DWORD *)(v88 + 204) = 0;
        }
      }

      // Non-related lines omitted...

      free(s1);
      free(s);
    }
  }
  free(s1);
  free(s);
  if ( v90 )
  {
    sub_4089EA(*a3, sub_4043FA);
    *a3 = 0;
  }
  sub_4043FA(v84);
  return v90;
}

__int64 __fastcall sub_419ADF(__int64 a1, unsigned int a2, __int64 a3, _QWORD *a4, __int64 *a5)
{
  if ( (unsigned int)SSL_set_fd(*(_QWORD *)(a1 + 72), a2) )
  {
    v21 = SSL_connect(*(_QWORD *)(a1 + 72));
    if ( (int)v21 > 0 )
    {
      if ( a3 )
      {
        v22 = sub_4185C1(a1, a3, a5);
        if ( v22 )
          goto LABEL_12;
      }
      if ( a4 )
        *a4 = 0;
      // NOTE: Calls the custom-implemented certificate checking algorithm.
      // NOTE: It's conditional on the (a1 + 52), which is actually mtls->no_certcheck.
      if ( !*(_DWORD *)(a1 + 52) && (v22 = sub_418E10(a1, (char)a5)) != 0 )
      {
LABEL_12:
        SSL_free(*(_QWORD *)(a1 + 72));
        SSL_CTX_free(*(_QWORD *)(a1 + 64));
        return v22;
      }
      else
      {
        *(_DWORD *)a1 = 1;
        return 0;
      }
    }
    else
    {
      if ( *__errno_location() == 4
        && ((v12 = v21, (unsigned int)SSL_get_error(*(_QWORD *)(a1 + 72), v21) == 2)
         || (v12 = v21, (unsigned int)SSL_get_error(*(_QWORD *)(a1 + 72), v21) == 3)) )
      {
        *a5 = sub_41672B((unsigned int)"operation aborted", v12, v13, v14, v15, v16);
      }
      else
      {
        error = SSL_get_error(*(_QWORD *)(a1 + 72), v21);
        *a5 = sub_419A0A(v21, error, "TLS handshake failed");
      }
      SSL_free(*(_QWORD *)(a1 + 72));
      SSL_CTX_free(*(_QWORD *)(a1 + 64));
      return 4;
    }
  }
  else
  {
    v5 = ERR_get_error();
    v6 = ERR_error_string(v5, 0);
    *a5 = sub_41672B((unsigned int)"cannot set the file descriptor for TLS: %s", v6, v7, v8, v9, v10);
    SSL_free(*(_QWORD *)(a1 + 72));
    SSL_CTX_free(*(_QWORD *)(a1 + 64));
    return 1;
  }
}

// NOTE: Completely custom certificate verification algorithm.
// NOTE: Not using the default verification which can be set by SSL_VERIFY_PEER.
__int64 __fastcall sub_418E10(__int64 a1, __int64 *a2)
{
  ptr = 0;
  if ( *(_DWORD *)(a1 + 4) )
    v66 = "TLS certificate verification failed";
  else
    v66 = "TLS certificate check failed";
  peer_certificate = SSL_get_peer_certificate(*(_QWORD *)(a1 + 72));
  if ( !peer_certificate )
  {
    *a2 = sub_41672B((unsigned int)"%s: no certificate was sent", (_DWORD)v66, v2, v3, v4, v5);
    return 3;
  }
  if ( *(_DWORD *)(a1 + 8) || *(_DWORD *)(a1 + 12) || *(_DWORD *)(a1 + 16) )
  {
  // NOTE: Certificate Pinning Algorithm.

    if ( *(_DWORD *)(a1 + 8) )
    {
      v54 = 32;
      v7 = EVP_sha256();
      if ( !(unsigned int)X509_digest(peer_certificate, v7, s1, &v54) )
      {
        *a2 = sub_41672B((unsigned int)"%s: error getting SHA256 fingerprint", (_DWORD)v66, v8, v9, v10, v11);
        X509_free(peer_certificate);
        return 3;
      }
      if ( memcmp(s1, (const void *)(a1 + 20), 0x20u) )
      {
LABEL_22:
        *a2 = sub_41672B(
                (unsigned int)"%s: the certificate fingerprint does not match",
                (_DWORD)v66,
                v12,
                v13,
                v14,
                v15);
        X509_free(peer_certificate);
        return 3;
      }
    }
    else if ( *(_DWORD *)(a1 + 12) )
    {
      v54 = 20;
      v16 = EVP_sha1();
      if ( !(unsigned int)X509_digest(peer_certificate, v16, s1, &v54) )
      {
        *a2 = sub_41672B((unsigned int)"%s: error getting SHA1 fingerprint", (_DWORD)v66, v17, v18, v19, v20);
        X509_free(peer_certificate);
        return 3;
      }
      if ( memcmp(s1, (const void *)(a1 + 20), 0x14u) )
        goto LABEL_22;
    }
    else
    {
      v54 = 16;
      v21 = EVP_md5();
      if ( !(unsigned int)X509_digest(peer_certificate, v21, s1, &v54) )
      {
        *a2 = sub_41672B((unsigned int)"%s: error getting MD5 fingerprint", (_DWORD)v66, v22, v23, v24, v25);
        X509_free(peer_certificate);
        return 3;
      }
      if ( memcmp(s1, (const void *)(a1 + 20), 0x10u) )
        goto LABEL_22;
    }
    X509_free(peer_certificate);
    return 0;
  }
  else
  {
    // NOTE: Check the certificate validation result.
    // NOTE: But ignores some errors.
    verify_result = SSL_get_verify_result();
    if ( verify_result && (*(_DWORD *)(a1 + 4) || verify_result != 20 && verify_result != 18 && verify_result != 19) )
    {
      v26 = X509_verify_cert_error_string(verify_result);
      *a2 = sub_41672B((unsigned int)"%s: %s", (_DWORD)v66, v26, v27, v28, v29);
      X509_free(peer_certificate);
      return 3;
    }
    idn2_to_ascii_lz(*(_QWORD *)(a1 + 56), &ptr, 9);
    v64 = 0;

    // NOTE: Hostname fetching and validating.
    ext_d2i = X509_get_ext_d2i(peer_certificate, 85, 0, 0);
    if ( ext_d2i )
    {
      v60 = sub_417DC4(ext_d2i);
      for ( i = 0; (int)i < v60; ++i )
      {
        v59 = sub_417DDE(ext_d2i, i);
        if ( *(_DWORD *)v59 == 2 )
        {
          v30 = **(int **)(v59 + 8);
          if ( v30 != strlen(*(const char **)(*(_QWORD *)(v59 + 8) + 8LL)) )
          {
            *a2 = sub_41672B(
                    (unsigned int)"%s: certificate subject alternative name contains NUL",
                    (_DWORD)v66,
                    v31,
                    v32,
                    v33,
                    v34);
            X509_free(peer_certificate);
            free(ptr);
            return 3;
          }
          if ( ptr )
            v35 = (const char *)ptr;
          else
            v35 = *(const char **)(a1 + 56);
          // NOTE: Calls the hostname comparing utility to verify hostname.
          v64 = sub_418D5E(v35, *(const char **)(*(_QWORD *)(v59 + 8) + 8LL));
          if ( v64 )
            break;
        }
      }
    }
    if ( !v64 )
    {
      subject_name = X509_get_subject_name(peer_certificate);
      if ( !subject_name )
      {
        *a2 = sub_41672B((unsigned int)"%s: cannot get certificate subject", (_DWORD)v66, v36, v37, v38, v39);
        X509_free(peer_certificate);
        free(ptr);
        return 3;
      }
      text_by_NID = X509_NAME_get_text_by_NID(subject_name, 13, 0, 0);
      s = (char *)sub_416624(text_by_NID + 1LL);
      if ( (unsigned int)X509_NAME_get_text_by_NID(subject_name, 13, s, (unsigned int)(text_by_NID + 1)) == -1 )
      {
        *a2 = sub_41672B((unsigned int)"%s: cannot get certificate common name", (_DWORD)v66, v40, v41, v42, v43);
        X509_free(peer_certificate);
        free(ptr);
        free(s);
        return 3;
      }
      v44 = text_by_NID;
      if ( v44 != strlen(s) )
      {
        *a2 = sub_41672B((unsigned int)"%s: certificate common name contains NUL", (_DWORD)v66, v45, v46, v47, v48);
        X509_free(peer_certificate);
        free(ptr);
        free(s);
        return 3;
      }
      if ( ptr )
        v49 = (const char *)ptr;
      else
        v49 = *(const char **)(a1 + 56);
      // NOTE: Calls the hostname comparing utility to verify hostname.
      v64 = sub_418D5E(v49, s);
      free(s);
    }
    X509_free(peer_certificate);
    free(ptr);
    if ( v64 )
    {
      return 0;
    }
    else
    {
      *a2 = sub_41672B(
              (unsigned int)"%s: the certificate owner does not match hostname %s",
              (_DWORD)v66,
              *(_QWORD *)(a1 + 56),
              v50,
              v51,
              v52);
      return 3;
    }
  }
}

// NOTE: Utility function to compare hostname.
_BOOL8 __fastcall sub_418D5E(char *a1, char *a2)
{
  char *s2; // [rsp+10h] [rbp-10h]
  char *s2a; // [rsp+10h] [rbp-10h]
  char *v5; // [rsp+18h] [rbp-8h]

  if ( !strncmp(a2, "*.", 2u) )
  {
    v5 = a2 + 2;
    s2 = strchr(a1, 46);
    if ( !s2 )
      return 0;
    s2a = s2 + 1;
  }
  else
  {
    v5 = a2;
    s2a = a1;
  }
  return *v5 && *s2a && strcasecmp(v5, s2a) == 0;
}