int smb_patch_tree_connect(unsigned char *pkt, size_t *pkt_len,
                           const char *new_ip)
{
    /*
     * SMB_TREE_CONNECT_PKT contem o UNC "\\192.168.175.128\\IPC$"
     * em UTF-16LE.  Esta funcao substitui o IP antigo por `new_ip`:
     *   1. encontra "\\\\" (0x5c 0x00 0x5c 0x00);
     *   2. posiciona o suffixo (\\IPC$...);
     *   3. escreve new_ip em UTF-16LE;
     *   4. desloca o suffixo para logo apos o novo IP;
     *   5. ajusta os campos de comprimento do SMB/NetBIOS.
     *
     * Retorna 0 em sucesso, -1 em erro.
     */
    size_t i, old_ip_end, suffix_len, new_ip_utf16_len;
    size_t old_ip_utf16_len, shift;
    size_t old_ip_start = (size_t)-1;

    if (pkt == NULL || new_ip == NULL || *pkt_len < 100)
        return -1;

    /* 1. localizar o inicio do IP: bytes formando "\\\\" em UTF-16 */
    for (i = 0; i + 3 < *pkt_len; i++) {
        if (pkt[i]==0x5c && pkt[i+1]==0x00 &&
            pkt[i+2]==0x5c && pkt[i+3]==0x00) {
            old_ip_start = i + 4;
            break;
        }
    }
    if (old_ip_start == (size_t)-1)
        return -1;

    /* 2. localizar o suffixo ("\\IPC$...") que comeca com 0x5c 0x00 */
    old_ip_end = old_ip_start;
    while (old_ip_end + 1 < *pkt_len &&
           !(pkt[old_ip_end]==0x5c && pkt[old_ip_end+1]==0x00 &&
             (old_ip_end == old_ip_start ||
              pkt[old_ip_end-2]!=0x5c)))
        old_ip_end++;
    if (old_ip_end >= *pkt_len)
        old_ip_end  = *pkt_len;

    suffix_len = *pkt_len - old_ip_end;
    old_ip_utf16_len = old_ip_end - old_ip_start;

    /* 3. comprimento UTF-16 do novo IP */
    new_ip_utf16_len = 0;
    for (const char *p = new_ip; *p != '\0'; p++)
        new_ip_utf16_len += 2;

    shift = old_ip_utf16_len > new_ip_utf16_len
              ? old_ip_utf16_len - new_ip_utf16_len
              : new_ip_utf16_len - old_ip_utf16_len;
    shift = old_ip_utf16_len - new_ip_utf16_len; /* positivo = encolhe */

    /* 4. deslocar o suffixo para a nova posicao */
    if (shift > 0) {
        memmove(pkt + old_ip_start + new_ip_utf16_len,
                pkt + old_ip_end, suffix_len);
        *pkt_len -= shift;
    } else if (shift < 0) {
        /* o novo IP e maior; assumimos que o buffer tem folga */
        memmove(pkt + old_ip_start + new_ip_utf16_len,
                pkt + old_ip_end, suffix_len);
        *pkt_len += (-shift);
    }
    /* shift == 0: nada a fazer */

    /* 5. escrever o novo IP em UTF-16LE */
    {
        size_t j;
        for (i = old_ip_start, j = 0; new_ip[j] != '\0'; j++) {
            pkt[i]   = (unsigned char)new_ip[j];
            pkt[i+1] = 0x00;
            i += 2;
        }
    }

    /* 6. ajustar o NetBIOS length nos bytes 2-3 do pacote:
          NetBIOS length = pkt_len - 4 (nao conta os 4 bytes do cabecalho) */
    {
        unsigned short nb_len = (unsigned short)(*pkt_len - 4);
        pkt[2] = (unsigned char)( nb_len       & 0xFF);
        pkt[3] = (unsigned char)((nb_len >>  8) & 0xFF);
    }

    /* 7. ajustar o ByteCount no ultimo campo de palavra (antes dos dados):
          no TreeConnect e o byte na posicao offset 0x2F (47) para
          pacotes com este formato.  Valor corrigido = pkt_len - offset_para_bytecount */
    /* Assumimos layout padrao do SMB TreeConnect:
       - cabecalho NetBIOS (4)
       - cabecalho SMB fixo (32)
       - palavra + dados variaveis */
    {
        unsigned short bytecount;
        size_t bc_offset;
        /* Procurar o campo ByteCount no padrao:
           apos o wordCount e os words, ha um short byteCount */
        /* No pacote TreeConnect o byteCount esta no offset 0x2F (47) */
        bc_offset = 0x2F;
        if (bc_offset + 1 < *pkt_len) {
            bytecount = (unsigned short)(*pkt_len - bc_offset - 2);
            pkt[bc_offset]     = (unsigned char)( bytecount       & 0xFF);
            pkt[bc_offset + 1] = (unsigned char)((bytecount >> 8) & 0xFF);
        }
    }

    return 0;
}