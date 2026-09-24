#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <ctype.h>

/*
 * Garante uma entrada @reboot para o binário sem alterar as entradas existentes.
 * Deve ser chamada após a transmissão; o chamador pode ignorar o erro de
 * agendamento sem alterar o resultado da transmissão.
 * Retorna 0 em caso de sucesso e -1 em caso de falha, definindo errno.
 */
int agendamento_automatico(const char *caminho_binario)
{
    FILE *captura_erro = NULL;
    FILE *leitura = NULL;
    FILE *escrita = NULL;
    char *linha = NULL;
    char *conteudo = NULL;
    size_t capacidade_conteudo = 0;
    size_t tamanho_conteudo = 0;
    size_t tamanho_caminho;
    ssize_t tamanho_linha;
    int stderr_salvo = -1;
    int erro_restauracao = 0;
    int erro_leitura = 0;
    int status_leitura;
    int sem_crontab = 0;
    int encontrou = 0;
    int erro;
    int resultado = -1;

    if (caminho_binario == NULL || caminho_binario[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    tamanho_caminho = strlen(caminho_binario);
    for (size_t i = 0; i < tamanho_caminho; ++i) {
        unsigned char c = (unsigned char)caminho_binario[i];
        if (c == '\n' || c == '\r' || isspace(c)) {
            errno = EINVAL;
            return -1;
        }
    }

    captura_erro = tmpfile();
    if (captura_erro == NULL) {
        return -1;
    }

    if (fflush(stderr) == EOF) {
        erro = errno ? errno : EIO;
        fclose(captura_erro);
        errno = erro;
        return -1;
    }

    stderr_salvo = dup(STDERR_FILENO);
    if (stderr_salvo < 0) {
        erro = errno;
        fclose(captura_erro);
        errno = erro;
        return -1;
    }

    if (dup2(fileno(captura_erro), STDERR_FILENO) < 0) {
        erro = errno;
        close(stderr_salvo);
        fclose(captura_erro);
        errno = erro;
        return -1;
    }

    leitura = popen("crontab -l", "r");
    erro = errno;

    if (dup2(stderr_salvo, STDERR_FILENO) < 0) {
        erro_restauracao = errno ? errno : EIO;
    }
    close(stderr_salvo);
    stderr_salvo = -1;

    if (leitura == NULL) {
        fclose(captura_erro);
        errno = erro ? erro : EIO;
        return -1;
    }

    while ((tamanho_linha = getline(&linha, &(size_t){0}, leitura)) >= 0) {
        size_t n = (size_t)tamanho_linha;

        if (n > SIZE_MAX - tamanho_conteudo) {
            erro_leitura = EOVERFLOW;
            break;
        }

        if (tamanho_conteudo + n > capacidade_conteudo) {
            size_t nova_capacidade = capacidade_conteudo ? capacidade_conteudo : 1024;
            while (nova_capacidade < tamanho_conteudo + n) {
                if (nova_capacidade > SIZE_MAX / 2) {
                    nova_capacidade = tamanho_conteudo + n;
                    break;
                }
                nova_capacidade *= 2;
            }

            char *novo_conteudo = realloc(conteudo, nova_capacidade);
            if (novo_conteudo == NULL) {
                erro_leitura = ENOMEM;
                break;
            }
            conteudo = novo_conteudo;
            capacidade_conteudo = nova_capacidade;
        }

        memcpy(conteudo + tamanho_conteudo, linha, n);
        tamanho_conteudo += n;

        size_t fim = n;
        if (fim > 0 && linha[fim - 1] == '\n') {
            --fim;
        }
        if (fim > 0 && linha[fim - 1] == '\r') {
            --fim;
        }

        size_t inicio = 0;
        while (inicio < fim && (linha[inicio] == ' ' || linha[inicio] == '\t')) {
            ++inicio;
        }

        static const char diretiva[] = "@reboot";
        if (fim - inicio >= sizeof(diretiva) - 1 &&
            memcmp(linha + inicio, diretiva, sizeof(diretiva) - 1) == 0) {
            size_t posicao = inicio + sizeof(diretiva) - 1;

            if (posicao < fim && (linha[posicao] == ' ' || linha[posicao] == '\t')) {
                while (posicao < fim &&
                       (linha[posicao] == ' ' || linha[posicao] == '\t')) {
                    ++posicao;
                }

                if (fim - posicao >= tamanho_caminho &&
                    memcmp(linha + posicao, caminho_binario, tamanho_caminho) == 0) {
                    size_t restante = posicao + tamanho_caminho;
                    while (restante < fim &&
                           (linha[restante] == ' ' || linha[restante] == '\t')) {
                        ++restante;
                    }
                    if (restante == fim) {
                        encontrou = 1;
                    }
                }
            }
        }
    }

    if (ferror(leitura) && erro_leitura == 0) {
        erro_leitura = errno ? errno : EIO;
    }
    free(linha);
    linha = NULL;

    status_leitura = pclose(leitura);
    leitura = NULL;

    if (erro_restauracao != 0) {
        erro = erro_restauracao;
        goto finalizar;
    }

    if (erro_leitura != 0) {
        erro = erro_leitura;
        goto finalizar;
    }

    if (status_leitura == -1) {
        erro = errno ? errno : EIO;
        goto finalizar;
    }

    if (fseek(captura_erro, 0, SEEK_SET) != 0) {
        erro = errno ? errno : EIO;
        goto finalizar;
    }

    {
        char *linha_erro = NULL;
        size_t capacidade_linha_erro = 0;
        ssize_t n;

        while ((n = getline(&linha_erro, &capacidade_linha_erro, captura_erro)) >= 0) {
            if (n > 0 && strstr(linha_erro, "no crontab") != NULL) {
                sem_crontab = 1;
            }
        }

        if (ferror(captura_erro)) {
            erro = errno ? errno : EIO;
            free(linha_erro);
            goto finalizar;
        }
        free(linha_erro);
    }

    if (!WIFEXITED(status_leitura) ||
        (WEXITSTATUS(status_leitura) != 0 && !sem_crontab)) {
        erro = EIO;
        goto finalizar;
    }

    if (encontrou) {
        resultado = 0;
        goto finalizar;
    }

    escrita = popen("crontab -", "w");
    if (escrita == NULL) {
        erro = errno ? errno : EIO;
        goto finalizar;
    }

    if (tamanho_conteudo > 0 &&
        fwrite(conteudo, 1, tamanho_conteudo, escrita) != tamanho_conteudo) {
        erro = errno ? errno : EIO;
        goto fechar_escrita;
    }

    if (tamanho_conteudo > 0 && conteudo[tamanho_conteudo - 1] != '\n') {
        if (fputc('\n', escrita) == EOF) {
            erro = errno ? errno : EIO;
            goto fechar_escrita;
        }
    }

    if (fprintf(escrita, "@reboot %s\n", caminho_binario) < 0) {
        erro = errno ? errno : EIO;
        goto fechar_escrita;
    }

    if (fflush(escrita) == EOF) {
        erro = errno ? errno : EIO;
        goto fechar_escrita;
    }

    erro = 0;

fechar_escrita:
    {
        int status_escrita = pclose(escrita);
        escrita = NULL;

        if (erro != 0) {
            goto finalizar;
        }
        if (status_escrita == -1) {
            erro = errno ? errno : EIO;
            goto finalizar;
        }
        if (!WIFEXITED(status_escrita) || WEXITSTATUS(status_escrita) != 0) {
            erro = EIO;
            goto finalizar;
        }
    }

    resultado = 0;

finalizar:
    free(conteudo);
    free(linha);
    if (leitura != NULL) {
        pclose(leitura);
    }
    if (escrita != NULL) {
        pclose(escrita);
    }
    if (captura_erro != NULL && fclose(captura_erro) != 0 && resultado == 0) {
        erro = errno ? errno : EIO;
        resultado = -1;
    }

    if (resultado != 0) {
        errno = erro ? erro : EIO;
    }
    return resultado;
}