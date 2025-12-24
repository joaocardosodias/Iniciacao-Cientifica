"""
Shell Manager API - Gerencia shells obtidas durante pentest.

Permite:
- Criar listeners para receber reverse shells
- Captar shells de ferramentas externas (Claude Desktop, Metasploit, etc.)
- Interagir com shells via WebSocket
- Manter histórico de comandos
"""

import asyncio
import socket as sock_module
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

# Usar o ShellManager global para integrar com WebSocket
from fragmentum.web.backend.services.shell_manager import get_shell_manager
from fragmentum.web.backend.models.shell import (
    ShellConnection,
    ShellType,
    ShellStatus,
    ListenerStatus,
)

router = APIRouter(prefix="/shells", tags=["shells"])


@dataclass 
class Listener:
    """Representa um listener para reverse shells."""
    id: str
    port: int
    protocol: str = "tcp"
    status: ListenerStatus = ListenerStatus.ACTIVE
    connection_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    server_socket: Optional[sock_module.socket] = None
    task: Optional[asyncio.Task] = None


# Storage apenas para listeners (shells são gerenciadas pelo ShellManager global)
_listeners: Dict[str, Listener] = {}


# Pydantic Models
class ListenerCreate(BaseModel):
    port: int
    protocol: str = "tcp"


class ListenerResponse(BaseModel):
    id: str
    port: int
    protocol: str
    status: str
    connection_count: int
    created_at: str


class ShellResponse(BaseModel):
    id: str
    target_ip: str
    target_port: int
    local_port: int
    shell_type: str
    status: str
    is_pty: bool
    created_at: str
    last_activity: str
    source: str


class CommandRequest(BaseModel):
    command: str


class HistoryEntryResponse(BaseModel):
    id: str
    shell_id: str
    command: str
    output: str
    timestamp: str


# Helper functions
def shell_to_response(shell: ShellConnection) -> ShellResponse:
    return ShellResponse(
        id=shell.id,
        target_ip=shell.target_ip,
        target_port=shell.target_port,
        local_port=shell.local_port,
        shell_type=shell.shell_type.value,
        status=shell.status.value,
        is_pty=shell.is_pty,
        created_at=shell.created_at.isoformat(),
        last_activity=shell.last_activity.isoformat(),
        source=shell.source,
    )


def listener_to_response(listener: Listener) -> ListenerResponse:
    return ListenerResponse(
        id=listener.id,
        port=listener.port,
        protocol=listener.protocol,
        status=listener.status.value,
        connection_count=listener.connection_count,
        created_at=listener.created_at.isoformat(),
    )


# Listener management - aceita conexões e registra no ShellManager global
async def accept_connections(listener: Listener):
    """Aceita conexões em um listener e registra no ShellManager global."""
    shell_manager = get_shell_manager()
    
    try:
        listener.server_socket = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_STREAM)
        listener.server_socket.setsockopt(sock_module.SOL_SOCKET, sock_module.SO_REUSEADDR, 1)
        listener.server_socket.bind(("0.0.0.0", listener.port))
        listener.server_socket.listen(5)
        listener.server_socket.setblocking(False)
        
        print(f"[Shell Manager] Listener started on port {listener.port}")
        
        loop = asyncio.get_event_loop()
        
        while listener.status == ListenerStatus.ACTIVE:
            try:
                client_socket, addr = await loop.sock_accept(listener.server_socket)
                
                # Criar shell usando o modelo correto
                shell_id = str(uuid.uuid4())[:8]
                now = datetime.now(timezone.utc)
                
                shell = ShellConnection(
                    id=shell_id,
                    target_ip=addr[0],
                    target_port=addr[1],
                    local_port=listener.port,
                    shell_type=ShellType.REVERSE,
                    status=ShellStatus.CONNECTED,
                    is_pty=False,
                    created_at=now,
                    last_activity=now,
                    source="listener",
                    socket_obj=client_socket,
                )
                
                # Registrar no ShellManager GLOBAL (usado pelo WebSocket)
                shell_manager.register_shell(shell)
                listener.connection_count += 1
                
                print(f"[Shell Manager] New shell from {addr[0]}:{addr[1]} -> ID: {shell_id}")
                
            except Exception as e:
                if listener.status == ListenerStatus.ACTIVE:
                    await asyncio.sleep(0.1)
                    
    except Exception as e:
        print(f"[Shell Manager] Listener error: {e}")
    finally:
        if listener.server_socket:
            listener.server_socket.close()


# ============================================================================
# API Endpoints - Listeners
# ============================================================================

@router.get("/listeners", response_model=List[ListenerResponse])
async def list_listeners():
    """Lista todos os listeners ativos."""
    return [listener_to_response(l) for l in _listeners.values()]


@router.post("/listeners", response_model=ListenerResponse)
async def create_listener(request: ListenerCreate):
    """Cria um novo listener para receber reverse shells."""
    # Verificar se porta já está em uso
    for l in _listeners.values():
        if l.port == request.port and l.status == ListenerStatus.ACTIVE:
            raise HTTPException(400, f"Port {request.port} already in use")
    
    listener_id = str(uuid.uuid4())[:8]
    listener = Listener(
        id=listener_id,
        port=request.port,
        protocol=request.protocol,
    )
    _listeners[listener_id] = listener
    
    # Iniciar task para aceitar conexões
    listener.task = asyncio.create_task(accept_connections(listener))
    
    return listener_to_response(listener)


@router.delete("/listeners/{listener_id}")
async def stop_listener(listener_id: str):
    """Para um listener."""
    if listener_id not in _listeners:
        raise HTTPException(404, "Listener not found")
    
    listener = _listeners[listener_id]
    listener.status = ListenerStatus.STOPPED
    
    if listener.server_socket:
        listener.server_socket.close()
    
    if listener.task:
        listener.task.cancel()
    
    del _listeners[listener_id]
    
    return {"message": f"Listener {listener_id} stopped"}


# ============================================================================
# API Endpoints - Shells (usando ShellManager global)
# ============================================================================

@router.get("", response_model=List[ShellResponse])
async def list_shells():
    """Lista todas as shells."""
    shell_manager = get_shell_manager()
    return [shell_to_response(s) for s in shell_manager.list_shells()]


@router.get("/{shell_id}", response_model=ShellResponse)
async def get_shell(shell_id: str):
    """Obtém detalhes de uma shell."""
    shell_manager = get_shell_manager()
    shell = shell_manager.get_shell(shell_id)
    if not shell:
        raise HTTPException(404, f"Shell not found: {shell_id}")
    return shell_to_response(shell)


@router.delete("/{shell_id}")
async def close_shell(shell_id: str):
    """Fecha uma shell."""
    shell_manager = get_shell_manager()
    
    if not shell_manager.get_shell(shell_id):
        raise HTTPException(404, "Shell not found")
    
    shell_manager.remove_shell(shell_id)
    
    return {"message": f"Shell {shell_id} closed"}


@router.get("/{shell_id}/history", response_model=List[HistoryEntryResponse])
async def get_shell_history(shell_id: str):
    """Obtém histórico de comandos de uma shell."""
    shell_manager = get_shell_manager()
    
    shell = shell_manager.get_shell(shell_id)
    if not shell:
        raise HTTPException(404, "Shell not found")
    
    history = shell_manager.get_history(shell_id)
    if not history:
        return []
    
    return [
        HistoryEntryResponse(
            id=entry.id,
            shell_id=entry.shell_id,
            command=entry.command,
            output=entry.output,
            timestamp=entry.timestamp.isoformat() if hasattr(entry.timestamp, 'isoformat') else str(entry.timestamp),
        )
        for entry in history.entries
    ]


@router.get("/{shell_id}/history/export")
async def export_shell_history(shell_id: str):
    """Exporta histórico de comandos como arquivo texto."""
    shell_manager = get_shell_manager()
    
    shell = shell_manager.get_shell(shell_id)
    if not shell:
        raise HTTPException(404, "Shell not found")
    
    history = shell_manager.get_history(shell_id)
    lines = [f"# Shell History - {shell.target_ip}:{shell.target_port}", f"# ID: {shell_id}", ""]
    
    if history:
        for entry in history.entries:
            lines.append(f"$ {entry.command}")
            if entry.output:
                lines.append(entry.output)
    
    content = "\n".join(lines)
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=shell-{shell_id}-history.txt"}
    )


@router.post("/{shell_id}/upgrade")
async def upgrade_shell(shell_id: str):
    """Tenta fazer upgrade da shell para PTY."""
    shell_manager = get_shell_manager()
    
    shell = shell_manager.get_shell(shell_id)
    if not shell:
        raise HTTPException(404, "Shell not found")
    
    if shell.status != ShellStatus.CONNECTED:
        raise HTTPException(400, "Shell not connected")
    
    if shell.is_pty:
        return {"success": True, "is_pty": True, "message": "Shell already has PTY"}
    
    try:
        success = await shell_manager.upgrade_to_pty(shell_id)
        return {
            "success": success,
            "is_pty": success,
            "message": "Shell upgraded to PTY" if success else "Failed to upgrade shell"
        }
    except Exception as e:
        return {"success": False, "is_pty": False, "message": str(e)}


@router.post("/{shell_id}/command")
async def send_command(shell_id: str, request: CommandRequest):
    """Envia um comando para uma shell."""
    shell_manager = get_shell_manager()
    
    shell = shell_manager.get_shell(shell_id)
    if not shell:
        raise HTTPException(404, "Shell not found")
    
    if shell.status != ShellStatus.CONNECTED:
        raise HTTPException(400, "Shell not connected")
    
    try:
        success = await shell_manager.send_command(shell_id, request.command)
        if success:
            return {"message": "Command sent"}
        else:
            raise HTTPException(500, "Failed to send command")
    except Exception as e:
        raise HTTPException(500, f"Failed to send command: {e}")


# ============================================================================
# Funções auxiliares para uso externo
# ============================================================================

def get_active_shells() -> List[ShellConnection]:
    """Retorna lista de shells ativas."""
    shell_manager = get_shell_manager()
    return shell_manager.get_shells_by_status(ShellStatus.CONNECTED)


def get_shell_count() -> int:
    """Retorna número de shells ativas."""
    return len(get_active_shells())
