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
    while [ "$(vm_state)" != "$want" ] && [ "$tries" -lt 60 ]; do
        sleep 2
        tries=$((tries + 1))
    done
    [ "$(vm_state)" = "$want" ]
}

command -v VBoxManage >/dev/null 2>&1 || { echo "  [erro] VBoxManage nao encontrado" >&2; exit 1; }

echo "================================================================"
echo "  RETORNO AO SNAPSHOT LIMPO"
echo "================================================================"
echo "  vm       : $VM"
echo "  snapshot : $SNAPSHOT"
echo "  aviso    : o estado atual sera descartado"

if [ "${LAB_RESET_CONFIRM:-}" != "yes" ]; then
    printf "  Exporte as evidencias antes de continuar. Confirmar? [s/N]: "
    read -r answer
    case "$answer" in
        s|S|sim|SIM|y|Y|yes|YES) ;;
        *) echo "  cancelado."; exit 0 ;;
    esac
fi

if [ "$(vm_state)" = "running" ]; then
    echo "  acao     : desligamento gracioso (ACPI)"
    VBoxManage controlvm "$VM" acpipowerbutton
    if ! wait_state "poweroff"; then
        echo "  acao     : forcando poweroff"
        VBoxManage controlvm "$VM" poweroff
        wait_state "poweroff" || { echo "  [erro] a VM nao desligou" >&2; exit 1; }
    fi
fi

echo "  acao     : restaurando snapshot"
VBoxManage snapshot "$VM" restore "$SNAPSHOT"

current="$(VBoxManage snapshot "$VM" list 2>/dev/null | grep -E "Name:" | grep "\*" || true)"
echo "  resultado: ${current:-snapshot restaurado}"
echo "================================================================"
