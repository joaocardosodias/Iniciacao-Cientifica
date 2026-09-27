#!/usr/bin/env bash
set -euo pipefail

VM="${LAB_VM_NAME:-IC}"
SNAPSHOT="${LAB_SNAPSHOT:-lab-clean-v1}"

vm_state() {
    VBoxManage showvminfo "$VM" --machinereadable 2>/dev/null \
        | grep -E "^VMState=" | cut -d'"' -f2
}

wait_state() {
    local want="$1" tries=0
    while [ "$(vm_state)" != "$want" ] && [ "$tries" -lt 30 ]; do
        sleep 2
        tries=$((tries + 1))
    done
    [ "$(vm_state)" = "$want" ]
}

command -v VBoxManage >/dev/null 2>&1 || { echo "  [erro] VBoxManage nao encontrado" >&2; exit 1; }

echo "================================================================"
echo "  INICIO LIMPO DA VM DE LABORATORIO"
echo "================================================================"
echo "  vm       : $VM"
echo "  snapshot : $SNAPSHOT"

if [ "$(vm_state)" = "running" ]; then
    echo "  acao     : desligando (descarta o estado atual)"
    VBoxManage controlvm "$VM" poweroff
    wait_state "poweroff" || { echo "  [erro] a VM nao desligou" >&2; exit 1; }
fi

echo "  acao     : restaurando snapshot"
VBoxManage snapshot "$VM" restore "$SNAPSHOT"

echo "  acao     : iniciando em modo headless"
VBoxManage startvm "$VM" --type headless >/dev/null

if VBoxManage list runningvms | grep -q "\"$VM\""; then
    echo "  resultado: VM em execucao"
else
    echo "  [erro] a VM nao apareceu em 'list runningvms'" >&2
    exit 1
fi
echo "================================================================"
