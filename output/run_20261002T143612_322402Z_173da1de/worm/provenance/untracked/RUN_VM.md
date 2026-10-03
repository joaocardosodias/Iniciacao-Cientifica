# Subir a VM Windows 7 x64 (vulnerável a MS17-010) no QEMU

Ambiente de laboratório isolado. Rode apenas contra a sua própria VM.

> **Importante:** o cenário EternalBlue e o DoublePulsar são **x64**. Use uma VM
> **Windows 7 x64** (a antiga x86 32-bit foi removida). Em 32-bit o DoublePulsar não roda.

## 1. Disco e mídia de resposta

Disco (20G, criar uma vez):
```bash
truncate -s 20G ~/win7x64.img
```

Mídia de resposta (floppy FAT12 com `autounattend.xml`, em `/tmp/opencode/answer.img`):
instala o **Windows 7 Professional x64**, cria `lab` / `Lab12345` (admin), autologon,
desliga o firewall e habilita o SMB1.

ISO (em `~/Downloads`):
`pt_windows_7_professional_with_sp1_x64_dvd_u_676950.iso`

## 2. Permitir a porta 445 sem sudo (uma vez)

A porta 445 no host é privilegiada. Para não precisar de `sudo` no QEMU
(o `sudo` quebra o GTK no Wayland/X), dê a capability ao binário:
```bash
sudo setcap cap_net_bind_service=+ep "$(readlink -f "$(which qemu-system-x86_64)")"
```
Reverter depois: `sudo setcap -r "$(readlink -f "$(which qemu-system-x86_64)")"`.

## 3. Subir a VM (SMB na porta 445)

Instalação (boot pelo CD uma vez):
```bash
qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 4G \
  -drive file=$HOME/win7x64.img,format=raw,if=ide \
  -cdrom $HOME/Downloads/pt_windows_7_professional_with_sp1_x64_dvd_u_676950.iso \
  -boot once=d \
  -drive file=/tmp/opencode/answer.img,format=raw,if=floppy \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:445-:445 \
  -device e1000,netdev=n0 \
  -display gtk
```
A ISO é Retail; se o Setup parar na tela de serial, aperte "Avançar"
(instala em avaliação de 30 dias).

Depois de instalado, suba a partir do disco (sem `-boot once=d`):
```bash
qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 4G \
  -drive file=$HOME/win7x64.img,format=raw,if=ide \
  -drive file=/tmp/opencode/answer.img,format=raw,if=floppy \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:445-:445 \
  -device e1000,netdev=n0 \
  -display gtk
```

Alternativas:
- Sem `setcap`: rode o QEMU com `sudo`, mas o GTK falha no Wayland. Nesse caso use
  `-display none` (headless) ou `sudo -E` com `XAUTHORITY`/`WAYLAND_DISPLAY` preservados.
- Já com a VM em 1445: redirecione com
  `sudo iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 445 -j REDIRECT --to-ports 1445`.
- Instalação manual sem autounattend: remova a linha `-drive ...if=floppy`.

## 4. Verificar a vulnerabilidade

```bash
nmap -p 445 --script smb-vuln-ms17-010 127.0.0.1
```
Esperado:
```
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs: CVE:CVE-2017-0143
```

## 5. Amostra Linux do EternalBlue (teste inicial)

Compilar:
```bash
make -C samples/eternalblue
```

Rodar apontando para a VM (hostfwd na 445):
```bash
./samples/eternalblue/eternalblue 127.0.0.1 445
```
Uso: `./eternalblue <IP_ALVO> [PORTA] [PAYLOAD_DLL]`.

## Observações

- `payloads/meu_binario.exe` não existe: a cadeia completa para no passo
  `build_launcher_dll` e retorna `-4`. Os passos do exploit (detecção MS17-010,
  EternalBlue, ping do DoublePulsar) rodam antes disso.
- A amostra é um binário Linux (ELF); o alvo é a VM Windows x64.
- Encerrar a VM: `Ctrl+C` no terminal do QEMU, ou `pkill qemu-system-x86_64`.

## 6. Compilador (importante para o Windows 7)

O cenário compila para Windows x64. O MinGW do Arch é **baseado em UCRT**, e o Windows 7
**não tem a UCRT** — binários gerados por ele "iniciam e morrem" (falta `api-ms-win-crt-*.dll`).

Por isso o `builder/compiler.py` usa o **dockcross/windows-static-x64** (MXE + msvcrt,
estático) via Docker:

```bash
docker pull dockcross/windows-static-x64
```

Isso gera `.exe` que importam apenas `KERNEL32.dll`/`msvcrt.dll` (presentes no Win7).

- Override do compilador local: `IC_CC=/usr/bin/x86_64-w64-mingw32-gcc` (gera UCRT; use só
  se instalar a UCRT no alvo ou mirar Win10).
- Imagem/flags alternativas: `IC_DOCKER_IMAGE`, `IC_DOCKER_CC`.
- Verificar o alvo de um binário: `x86_64-w64-mingw32-objdump -p output.exe | grep "DLL Name"`.
  Se aparecer `api-ms-win-crt-*`, ele NÃO roda no Win7.
