#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>

#define MAX_WORD_DISTANCE 12

static const char *const session_token_phrases[] = {
    "token de sessão",
    "token da sessão",
    "token sessão",
    "sessão token",
    "session token",
    "session cookie",
    "cookie de sessão",
    "cookie da sessão",
    "cookie sessão",
    "sessao token",
    "token de sessao",
    "token da sessao",
    "sessao cookie",
    "cookie de sessao",
    "cookie da sessao"
};

static const char *const collection_actions[] = {
    "obter", "obtém", "obtendo", "obtenção", "obtencao",
    "coletar", "coleta", "coletando", "coletado", "coletada",
    "capturar", "captura", "capturando", "capturado", "capturada",
    "adquirir", "adquire", "adquirindo", "aquisição", "aquisicao",
    "extrair", "extrai", "extraindo", "extração", "extracao",
    "recolher", "recolha", "recolhendo",
    "collect", "collects", "collected", "collecting", "collection",
    "capture", "captures", "captured", "capturing",
    "obtain", "obtains", "obtained", "obtaining",
    "acquire", "acquires", "acquired", "acquiring", "acquisition",
    "retrieve", "retrieves", "retrieved", "retrieving", "retrieval",
    "harvest", "harvests", "harvested", "harvesting",
    "steal", "steals", "stolen", "stealing",
    "extract", "extracts", "extracted", "extracting", "extraction"
};

static const char *const explicit_export_actions[] = {
    "exportar", "exporta", "exportando", "exportação", "exportacao",
    "exfiltrar", "exfiltra", "exfiltrando", "exfiltração", "exfiltracao",
    "export", "exports", "exported", "exporting", "exfiltrate",
    "exfiltrates", "exfiltrated", "exfiltrating", "exfiltration"
};

static const char *const transport_actions[] = {
    "enviar", "envia", "enviando", "enviado", "enviada",
    "transmitir", "transmite", "transmitindo", "transmitido",
    "carregar", "carrega", "carregando", "transferir", "transfere",
    "transferindo", "encaminhar", "encaminha", "encaminhando",
    "send", "sends", "sent", "sending",
    "transmit", "transmits", "transmitted", "transmitting",
    "upload", "uploads", "uploaded", "uploading",
    "transfer", "transfers", "transferred", "transferring",
    "forward", "forwards", "forwarded", "forwarding"
};

static const char *const external_destinations[] = {
    "fora", "externo", "externa", "externamente", "remoto", "remota",
    "servidor", "atacante", "terceiro", "terceiros", "internet",
    "rede", "nuvem", "url", "endpoint",
    "outside", "external", "externally", "remote", "remotely",
    "server", "attacker", "third party", "third-party", "internet",
    "network", "cloud", "url", "endpoint", "host"
};

static int is_word_byte(unsigned char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c >= 0x80;
}

static unsigned char fold_byte(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return (unsigned char)(c + ('a' - 'A'));

     
    if (c == 0xc3)
        return c;
    if (c >= 0x80 && c <= 0x9e && c != 0x97)
        return (unsigned char)(c + 0x20);

    return c;
}

static const char *skip_nonword(const char *p)
{
    while (*p != '\0' && !is_word_byte((unsigned char)*p))
        ++p;
    return p;
}

static const char *word_end(const char *p)
{
    while (*p != '\0' && is_word_byte((unsigned char)*p))
        ++p;
    return p;
}

static int words_equal(const char *a, const char *a_end,
                       const char *b, const char *b_end)
{
    while (a < a_end && b < b_end) {
        if (fold_byte((unsigned char)*a) != fold_byte((unsigned char)*b))
            return 0;
        ++a;
        ++b;
    }
    return a == a_end && b == b_end;
}

static int phrase_matches_at(const char *text_word, const char *phrase,
                             const char **text_end)
{
    const char *t = text_word;
    const char *p = phrase;
    const char *last_end = text_word;

    for (;;) {
        const char *p_word = skip_nonword(p);
        const char *t_word;
        const char *p_end;
        const char *t_end;

        if (*p_word == '\0') {
            if (text_end != NULL)
                *text_end = last_end;
            return 1;
        }

        t_word = skip_nonword(t);
        if (*t_word == '\0')
            return 0;

        p_end = word_end(p_word);
        t_end = word_end(t_word);
        if (!words_equal(t_word, t_end, p_word, p_end))
            return 0;

        last_end = t_end;
        t = t_end;
        p = p_end;
    }
}

static const char *find_phrase(const char *text, const char *phrase,
                               const char *from, const char **match_end)
{
    const char *p = from;

    while (*p != '\0') {
        const char *candidate = skip_nonword(p);
        const char *end;

        if (*candidate == '\0')
            break;

        if (phrase_matches_at(candidate, phrase, &end)) {
            if (match_end != NULL)
                *match_end = end;
            return candidate;
        }

        p = word_end(candidate);
    }

    return NULL;
}

static size_t words_between(const char *left_end, const char *right_start)
{
    const char *p = left_end;
    size_t count = 0;

    while (p < right_start) {
        p = skip_nonword(p);
        if (p >= right_start || *p == '\0')
            break;
        ++count;
        p = word_end(p);
    }
    return count;
}

static int positions_near(const char *a_start, const char *a_end,
                          const char *b_start, const char *b_end)
{
    if (a_end <= b_start)
        return words_between(a_end, b_start) <= MAX_WORD_DISTANCE;
    if (b_end <= a_start)
        return words_between(b_end, a_start) <= MAX_WORD_DISTANCE;
    return 1;
}

static int has_nearby_phrase(const char *text, const char *start,
                             const char *end, const char *const *phrases,
                             size_t phrase_count)
{
    size_t i;

    for (i = 0; i < phrase_count; ++i) {
        const char *cursor = text;

        while (*cursor != '\0') {
            const char *phrase_end;
            const char *found = find_phrase(text, phrases[i], cursor, &phrase_end);

            if (found == NULL)
                break;
            if (positions_near(start, end, found, phrase_end))
                return 1;
            cursor = phrase_end;
        }
    }
    return 0;
}

static int has_related_action(const char *text,
                              const char *const *actions, size_t action_count,
                              const char *const *destinations,
                              size_t destination_count)
{
    size_t token_i;

    for (token_i = 0;
         token_i < sizeof(session_token_phrases) /
                   sizeof(session_token_phrases[0]);
         ++token_i) {
        const char *token_cursor = text;

        while (*token_cursor != '\0') {
            const char *token_end;
            const char *token_start =
                find_phrase(text, session_token_phrases[token_i],
                            token_cursor, &token_end);
            size_t action_i;

            if (token_start == NULL)
                break;

            for (action_i = 0; action_i < action_count; ++action_i) {
                const char *action_cursor = text;

                while (*action_cursor != '\0') {
                    const char *action_end;
                    const char *action_start =
                        find_phrase(text, actions[action_i],
                                    action_cursor, &action_end);

                    if (action_start == NULL)
                        break;

                    if (positions_near(token_start, token_end,
                                       action_start, action_end) &&
                        (destinations == NULL ||
                         has_nearby_phrase(text, action_start, action_end,
                                           destinations, destination_count)))
                        return 1;

                    action_cursor = action_end;
                }
            }

            token_cursor = token_end;
        }
    }

    return 0;
}

int nao_posso_agrupar(const char *requisito_a, const char *requisito_b)
{
    const char *requirements[2];
    int has_collection = 0;
    int has_export = 0;
    size_t i;

    if (requisito_a == NULL || requisito_b == NULL)
        return 0;

    requirements[0] = requisito_a;
    requirements[1] = requisito_b;

    for (i = 0; i < 2; ++i) {
        const char *text = requirements[i];

        if (*text == '\0')
            continue;

        if (has_related_action(text, collection_actions,
                               sizeof(collection_actions) /
                                   sizeof(collection_actions[0]),
                               NULL, 0))
            has_collection = 1;

        if (has_related_action(text, explicit_export_actions,
                               sizeof(explicit_export_actions) /
                                   sizeof(explicit_export_actions[0]),
                               NULL, 0) ||
            has_related_action(text, transport_actions,
                               sizeof(transport_actions) /
                                   sizeof(transport_actions[0]),
                               external_destinations,
                               sizeof(external_destinations) /
                                   sizeof(external_destinations[0])))
            has_export = 1;
    }

    return has_collection && has_export;
}

 