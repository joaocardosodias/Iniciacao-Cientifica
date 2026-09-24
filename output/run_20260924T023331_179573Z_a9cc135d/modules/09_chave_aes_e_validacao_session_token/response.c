#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

enum {
    CHAVE_AES_VALIDACAO_OK = 0,
    CHAVE_AES_VALIDACAO_ARGUMENTO_INVALIDO = -1,
    CHAVE_AES_VALIDACAO_TOKEN_INVALIDO = -2,
    CHAVE_AES_VALIDACAO_BUFFER_INSUFICIENTE = -3,
    CHAVE_AES_VALIDACAO_ERRO_CRIPTOGRAFICO = -4
};

int chave_aes_e_validacao_session_token(const char *json_entrada,
                                        const uint8_t *chave_aes,
                                        char *json_transmissao,
                                        size_t capacidade_json)
{
    static const char needle[] = "\"session_token\":\"";
    const char *token;
    const char *fim;
    size_t comprimento_token = 0;
    unsigned char chave_base64[EVP_ENCODE_LENGTH(32)];
    int comprimento_base64;
    int comprimento_json;

    if (json_entrada == NULL || chave_aes == NULL ||
        json_transmissao == NULL || capacidade_json == 0) {
        return CHAVE_AES_VALIDACAO_ARGUMENTO_INVALIDO;
    }

    token = strstr(json_entrada, needle);
    if (token == NULL) {
        return CHAVE_AES_VALIDACAO_TOKEN_INVALIDO;
    }
    token += strlen(needle);

    fim = token;
    while (*fim != '\0') {
        if (*fim == '"') {
            break;
        }
        if (*fim == '\\') {
            if (fim[1] == '\0') {
                return CHAVE_AES_VALIDACAO_TOKEN_INVALIDO;
            }
            fim += 2;
            comprimento_token += 2;
            continue;
        }
        ++fim;
        ++comprimento_token;
    }

    if (*fim != '"' || comprimento_token == 0) {
        return CHAVE_AES_VALIDACAO_TOKEN_INVALIDO;
    }

    comprimento_base64 = EVP_EncodeBlock(chave_base64, chave_aes, 32);
    if (comprimento_base64 <= 0) {
        return CHAVE_AES_VALIDACAO_ERRO_CRIPTOGRAFICO;
    }

    comprimento_json = snprintf(json_transmissao, capacidade_json,
                                "{\"aes_key\":\"%.*s\"}",
                                comprimento_base64, chave_base64);
    if (comprimento_json < 0 || (size_t)comprimento_json >= capacidade_json) {
        json_transmissao[0] = '\0';
        return CHAVE_AES_VALIDACAO_BUFFER_INSUFICIENTE;
    }

    return CHAVE_AES_VALIDACAO_OK;
}