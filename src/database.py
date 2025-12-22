"""
FRAGMENTUM Database Module
SQLite-based persistence for intelligence data.
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import asdict


# Default database path
DEFAULT_DB_PATH = Path(__file__).parent / "results" / "fragmentum.db"


class FragmentumDB:
    """SQLite database manager for FRAGMENTUM."""
    
    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Establish database connection."""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row  # Access columns by name
        # Enable foreign keys
        self.conn.execute("PRAGMA foreign_keys = ON")
    
    def _create_tables(self):
        """Create database schema."""
        cursor = self.conn.cursor()
        
        # Targets (hosts)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                hostname TEXT,
                os TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Services
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                service TEXT,
                version TEXT,
                banner TEXT,
                anonymous_access INTEGER DEFAULT 0,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id),
                UNIQUE(target_id, port, protocol)
            )
        """)
        
        # Vulnerabilities
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                service_id INTEGER,
                name TEXT NOT NULL,
                cve TEXT,
                severity TEXT,
                description TEXT,
                exploited INTEGER DEFAULT 0,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id),
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
        """)
        
        # Credentials
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                service TEXT,
                port INTEGER,
                username TEXT NOT NULL,
                password TEXT,
                valid INTEGER DEFAULT 1,
                source TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id),
                UNIQUE(target_id, service, username, password)
            )
        """)
        
        # Loot (files, data extracted)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS loot (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                loot_type TEXT NOT NULL,
                name TEXT,
                content TEXT,
                path TEXT,
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        """)
        
        # Closed ports (to avoid retrying)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS closed_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id),
                UNIQUE(target_id, port)
            )
        """)

        # Operations (execution history)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                scenario_id TEXT,
                intent TEXT,
                provider TEXT,
                model TEXT,
                mode TEXT,
                stealth TEXT,
                result TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        """)
        
        # Commands (command history per operation)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                step_number INTEGER,
                step_description TEXT,
                command TEXT NOT NULL,
                output TEXT,
                success INTEGER,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (operation_id) REFERENCES operations(id),
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        """)
        
        # Users discovered
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                source TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id),
                UNIQUE(target_id, username)
            )
        """)
        
        # RPC actions (Metasploit RPC execution history)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rpc_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id INTEGER NOT NULL,
                step_number INTEGER,
                action_type TEXT NOT NULL,
                module_name TEXT,
                options_json TEXT,
                payload TEXT,
                session_id INTEGER,
                result_success INTEGER,
                result_data TEXT,
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (operation_id) REFERENCES operations(id)
            )
        """)
        
        # MSF sessions (Metasploit session tracking)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS msf_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id INTEGER NOT NULL,
                msf_session_id INTEGER NOT NULL,
                session_type TEXT,
                target_host TEXT,
                target_port INTEGER,
                via_exploit TEXT,
                via_payload TEXT,
                platform TEXT,
                arch TEXT,
                opened_at TIMESTAMP,
                closed_at TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (operation_id) REFERENCES operations(id)
            )
        """)
        
        self.conn.commit()
    
    # ==================== TARGET OPERATIONS ====================
    
    def get_or_create_target(self, ip: str) -> int:
        """Get target ID, creating if doesn't exist."""
        cursor = self.conn.cursor()
        
        # Try to get existing
        cursor.execute("SELECT id FROM targets WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        
        if row:
            # Update last_seen
            cursor.execute(
                "UPDATE targets SET last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                (row['id'],)
            )
            self.conn.commit()
            return row['id']
        
        # Create new
        cursor.execute("INSERT INTO targets (ip) VALUES (?)", (ip,))
        self.conn.commit()
        return cursor.lastrowid
    
    def update_target(self, ip: str, hostname: str = None, os: str = None):
        """Update target information."""
        target_id = self.get_or_create_target(ip)
        
        updates = []
        params = []
        
        if hostname:
            updates.append("hostname = ?")
            params.append(hostname)
        if os:
            updates.append("os = ?")
            params.append(os)
        
        if updates:
            params.append(target_id)
            query = f"UPDATE targets SET {', '.join(updates)} WHERE id = ?"
            self.conn.execute(query, params)
            self.conn.commit()
    
    def get_all_targets(self) -> List[Dict]:
        """Get all targets with summary info."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                t.id, t.ip, t.hostname, t.os, t.first_seen, t.last_seen,
                (SELECT COUNT(*) FROM services WHERE target_id = t.id) as service_count,
                (SELECT COUNT(*) FROM vulnerabilities WHERE target_id = t.id) as vuln_count,
                (SELECT COUNT(*) FROM credentials WHERE target_id = t.id) as cred_count
            FROM targets t
            ORDER BY t.last_seen DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    # ==================== SERVICE OPERATIONS ====================
    
    def add_service(self, ip: str, port: int, service: str, version: str = "",
                   protocol: str = "tcp", banner: str = "", anonymous: bool = False) -> int:
        """Add or update a service."""
        target_id = self.get_or_create_target(ip)
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO services (target_id, port, protocol, service, version, banner, anonymous_access)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id, port, protocol) DO UPDATE SET
                    service = excluded.service,
                    version = excluded.version,
                    banner = COALESCE(excluded.banner, banner),
                    anonymous_access = excluded.anonymous_access
            """, (target_id, port, protocol, service, version, banner, int(anonymous)))
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error:
            return -1
    
    def get_services(self, ip: str = None) -> List[Dict]:
        """Get services, optionally filtered by target IP."""
        cursor = self.conn.cursor()
        
        if ip:
            cursor.execute("""
                SELECT s.*, t.ip 
                FROM services s
                JOIN targets t ON s.target_id = t.id
                WHERE t.ip = ?
                ORDER BY s.port
            """, (ip,))
        else:
            cursor.execute("""
                SELECT s.*, t.ip 
                FROM services s
                JOIN targets t ON s.target_id = t.id
                ORDER BY t.ip, s.port
            """)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_service_by_port(self, ip: str, port: int) -> Optional[Dict]:
        """Get a specific service by IP and port."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT s.*, t.ip 
            FROM services s
            JOIN targets t ON s.target_id = t.id
            WHERE t.ip = ? AND s.port = ?
        """, (ip, port))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    # ==================== VULNERABILITY OPERATIONS ====================
    
    def add_vulnerability(self, ip: str, name: str, cve: str = None, 
                         port: int = None, severity: str = None,
                         description: str = None) -> int:
        """Add a vulnerability."""
        target_id = self.get_or_create_target(ip)
        cursor = self.conn.cursor()
        
        # Get service_id if port provided
        service_id = None
        if port:
            cursor.execute("""
                SELECT id FROM services WHERE target_id = ? AND port = ?
            """, (target_id, port))
            row = cursor.fetchone()
            if row:
                service_id = row['id']
        
        # Check if already exists
        cursor.execute("""
            SELECT id FROM vulnerabilities 
            WHERE target_id = ? AND name = ?
        """, (target_id, name))
        
        if cursor.fetchone():
            return -1  # Already exists
        
        cursor.execute("""
            INSERT INTO vulnerabilities (target_id, service_id, name, cve, severity, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (target_id, service_id, name, cve, severity, description))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_vulnerabilities(self, ip: str = None) -> List[Dict]:
        """Get vulnerabilities, optionally filtered by target IP."""
        cursor = self.conn.cursor()
        
        if ip:
            cursor.execute("""
                SELECT v.*, t.ip, s.port, s.service
                FROM vulnerabilities v
                JOIN targets t ON v.target_id = t.id
                LEFT JOIN services s ON v.service_id = s.id
                WHERE t.ip = ?
                ORDER BY v.discovered_at DESC
            """, (ip,))
        else:
            cursor.execute("""
                SELECT v.*, t.ip, s.port, s.service
                FROM vulnerabilities v
                JOIN targets t ON v.target_id = t.id
                LEFT JOIN services s ON v.service_id = s.id
                ORDER BY t.ip, v.discovered_at DESC
            """)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def mark_exploited(self, ip: str, vuln_name: str):
        """Mark a vulnerability as exploited."""
        target_id = self.get_or_create_target(ip)
        self.conn.execute("""
            UPDATE vulnerabilities SET exploited = 1
            WHERE target_id = ? AND name = ?
        """, (target_id, vuln_name))
        self.conn.commit()

    # ==================== CREDENTIAL OPERATIONS ====================
    
    def add_credential(self, ip: str, username: str, password: str = None,
                      service: str = None, port: int = None, 
                      valid: bool = True, source: str = None) -> int:
        """Add a credential."""
        target_id = self.get_or_create_target(ip)
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO credentials (target_id, service, port, username, password, valid, source)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id, service, username, password) DO UPDATE SET
                    valid = excluded.valid,
                    source = COALESCE(excluded.source, source)
            """, (target_id, service, port, username, password, int(valid), source))
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error:
            return -1
    
    def get_credentials(self, ip: str = None, valid_only: bool = False) -> List[Dict]:
        """Get credentials, optionally filtered by target IP."""
        cursor = self.conn.cursor()
        
        where_clauses = []
        params = []
        
        if ip:
            where_clauses.append("t.ip = ?")
            params.append(ip)
        if valid_only:
            where_clauses.append("c.valid = 1")
        
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        cursor.execute(f"""
            SELECT c.*, t.ip
            FROM credentials c
            JOIN targets t ON c.target_id = t.id
            {where_sql}
            ORDER BY t.ip, c.service
        """, params)
        
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== USER OPERATIONS ====================
    
    def add_user(self, ip: str, username: str, source: str = None) -> int:
        """Add a discovered user."""
        target_id = self.get_or_create_target(ip)
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO users (target_id, username, source)
                VALUES (?, ?, ?)
                ON CONFLICT(target_id, username) DO NOTHING
            """, (target_id, username, source))
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error:
            return -1
    
    def get_users(self, ip: str = None) -> List[Dict]:
        """Get discovered users."""
        cursor = self.conn.cursor()
        
        if ip:
            cursor.execute("""
                SELECT u.*, t.ip
                FROM users u
                JOIN targets t ON u.target_id = t.id
                WHERE t.ip = ?
                ORDER BY u.username
            """, (ip,))
        else:
            cursor.execute("""
                SELECT u.*, t.ip
                FROM users u
                JOIN targets t ON u.target_id = t.id
                ORDER BY t.ip, u.username
            """)
        
        return [dict(row) for row in cursor.fetchall()]
    
    # ==================== LOOT OPERATIONS ====================
    
    def add_loot(self, ip: str, loot_type: str, content: str,
                name: str = None, path: str = None) -> int:
        """Add loot (extracted data/files)."""
        target_id = self.get_or_create_target(ip)
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO loot (target_id, loot_type, name, content, path)
            VALUES (?, ?, ?, ?, ?)
        """, (target_id, loot_type, name, content, path))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_loot(self, ip: str = None, loot_type: str = None) -> List[Dict]:
        """Get loot, optionally filtered."""
        cursor = self.conn.cursor()
        
        where_clauses = []
        params = []
        
        if ip:
            where_clauses.append("t.ip = ?")
            params.append(ip)
        if loot_type:
            where_clauses.append("l.loot_type = ?")
            params.append(loot_type)
        
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        cursor.execute(f"""
            SELECT l.*, t.ip
            FROM loot l
            JOIN targets t ON l.target_id = t.id
            {where_sql}
            ORDER BY l.collected_at DESC
        """, params)
        
        return [dict(row) for row in cursor.fetchall()]

    # ==================== CLOSED PORTS ====================
    
    def add_closed_port(self, ip: str, port: int):
        """Mark a port as closed."""
        target_id = self.get_or_create_target(ip)
        try:
            self.conn.execute("""
                INSERT INTO closed_ports (target_id, port)
                VALUES (?, ?)
                ON CONFLICT(target_id, port) DO NOTHING
            """, (target_id, port))
            self.conn.commit()
        except sqlite3.Error:
            pass
    
    def get_closed_ports(self, ip: str) -> List[int]:
        """Get list of closed ports for a target."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT cp.port
            FROM closed_ports cp
            JOIN targets t ON cp.target_id = t.id
            WHERE t.ip = ?
            ORDER BY cp.port
        """, (ip,))
        return [row['port'] for row in cursor.fetchall()]
    
    def is_port_closed(self, ip: str, port: int) -> bool:
        """Check if a port is known to be closed."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 1 FROM closed_ports cp
            JOIN targets t ON cp.target_id = t.id
            WHERE t.ip = ? AND cp.port = ?
        """, (ip, port))
        return cursor.fetchone() is not None
    
    # ==================== OPERATION HISTORY ====================
    
    def start_operation(self, ip: str, scenario_id: str = None, intent: str = None,
                       provider: str = None, model: str = None, 
                       mode: str = None, stealth: str = None) -> int:
        """Start a new operation and return its ID."""
        target_id = self.get_or_create_target(ip)
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO operations (target_id, scenario_id, intent, provider, model, mode, stealth)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_id, scenario_id, intent, provider, model, mode, stealth))
        self.conn.commit()
        return cursor.lastrowid
    
    def finish_operation(self, operation_id: int, result: str):
        """Mark an operation as finished."""
        self.conn.execute("""
            UPDATE operations 
            SET result = ?, finished_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (result, operation_id))
        self.conn.commit()
    
    def log_command(self, operation_id: int, ip: str, command: str, 
                   output: str = None, success: bool = None,
                   step_number: int = None, step_description: str = None) -> int:
        """Log a command execution."""
        target_id = self.get_or_create_target(ip)
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO commands (operation_id, target_id, step_number, step_description, command, output, success)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (operation_id, target_id, step_number, step_description, command, output, 
              int(success) if success is not None else None))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_operations(self, ip: str = None, limit: int = 20) -> List[Dict]:
        """Get operation history."""
        cursor = self.conn.cursor()
        
        if ip:
            cursor.execute("""
                SELECT o.*, t.ip
                FROM operations o
                JOIN targets t ON o.target_id = t.id
                WHERE t.ip = ?
                ORDER BY o.started_at DESC
                LIMIT ?
            """, (ip, limit))
        else:
            cursor.execute("""
                SELECT o.*, t.ip
                FROM operations o
                JOIN targets t ON o.target_id = t.id
                ORDER BY o.started_at DESC
                LIMIT ?
            """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_commands(self, operation_id: int = None, ip: str = None, limit: int = 50) -> List[Dict]:
        """Get command history."""
        cursor = self.conn.cursor()
        
        if operation_id:
            cursor.execute("""
                SELECT c.*, t.ip
                FROM commands c
                JOIN targets t ON c.target_id = t.id
                WHERE c.operation_id = ?
                ORDER BY c.executed_at
            """, (operation_id,))
        elif ip:
            cursor.execute("""
                SELECT c.*, t.ip
                FROM commands c
                JOIN targets t ON c.target_id = t.id
                WHERE t.ip = ?
                ORDER BY c.executed_at DESC
                LIMIT ?
            """, (ip, limit))
        else:
            cursor.execute("""
                SELECT c.*, t.ip
                FROM commands c
                JOIN targets t ON c.target_id = t.id
                ORDER BY c.executed_at DESC
                LIMIT ?
            """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]

    # ==================== RPC ACTION LOGGING ====================
    
    def log_rpc_action(self, operation_id: int, action_type: str,
                       module_name: str = None, options: dict = None,
                       payload: str = None, session_id: int = None,
                       result_success: bool = None, result_data: str = None,
                       error_message: str = None, step_number: int = None) -> int:
        """
        Log a Metasploit RPC action execution.
        
        Args:
            operation_id: ID of the parent operation
            action_type: Type of action (exploit, auxiliary, session_cmd, pivot)
            module_name: Metasploit module name
            options: Module options as dict (will be JSON serialized)
            payload: Payload name if applicable
            session_id: Session ID if applicable
            result_success: Whether the action succeeded
            result_data: Result data as string
            error_message: Error message if failed
            step_number: Step number within the operation
            
        Returns:
            ID of the inserted record
        """
        import json
        cursor = self.conn.cursor()
        
        options_json = json.dumps(options) if options else None
        
        cursor.execute("""
            INSERT INTO rpc_actions (
                operation_id, step_number, action_type, module_name,
                options_json, payload, session_id, result_success,
                result_data, error_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            operation_id, step_number, action_type, module_name,
            options_json, payload, session_id,
            int(result_success) if result_success is not None else None,
            result_data, error_message
        ))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_rpc_actions(self, operation_id: int = None, limit: int = 50) -> List[Dict]:
        """Get RPC action history."""
        import json
        cursor = self.conn.cursor()
        
        if operation_id:
            cursor.execute("""
                SELECT * FROM rpc_actions
                WHERE operation_id = ?
                ORDER BY created_at
            """, (operation_id,))
        else:
            cursor.execute("""
                SELECT * FROM rpc_actions
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
        
        results = []
        for row in cursor.fetchall():
            row_dict = dict(row)
            # Parse options_json back to dict
            if row_dict.get('options_json'):
                try:
                    row_dict['options'] = json.loads(row_dict['options_json'])
                except json.JSONDecodeError:
                    row_dict['options'] = {}
            else:
                row_dict['options'] = {}
            results.append(row_dict)
        
        return results

    # ==================== MSF SESSION LOGGING ====================
    
    def log_session(self, operation_id: int, msf_session_id: int,
                    session_type: str = None, target_host: str = None,
                    target_port: int = None, via_exploit: str = None,
                    via_payload: str = None, platform: str = None,
                    arch: str = None, opened_at: datetime = None) -> int:
        """
        Log a new Metasploit session or update existing one.
        
        Args:
            operation_id: ID of the parent operation
            msf_session_id: Metasploit's session ID
            session_type: Type of session (shell, meterpreter)
            target_host: Target host IP
            target_port: Target port
            via_exploit: Exploit used to create session
            via_payload: Payload used
            platform: Target platform
            arch: Target architecture
            opened_at: When the session was opened
            
        Returns:
            ID of the inserted/updated record
        """
        cursor = self.conn.cursor()
        
        # Check if session already exists for this operation
        cursor.execute("""
            SELECT id FROM msf_sessions
            WHERE operation_id = ? AND msf_session_id = ?
        """, (operation_id, msf_session_id))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing session
            cursor.execute("""
                UPDATE msf_sessions SET
                    session_type = COALESCE(?, session_type),
                    target_host = COALESCE(?, target_host),
                    target_port = COALESCE(?, target_port),
                    via_exploit = COALESCE(?, via_exploit),
                    via_payload = COALESCE(?, via_payload),
                    platform = COALESCE(?, platform),
                    arch = COALESCE(?, arch)
                WHERE id = ?
            """, (session_type, target_host, target_port, via_exploit,
                  via_payload, platform, arch, existing['id']))
            self.conn.commit()
            return existing['id']
        
        # Insert new session
        cursor.execute("""
            INSERT INTO msf_sessions (
                operation_id, msf_session_id, session_type, target_host,
                target_port, via_exploit, via_payload, platform, arch, opened_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            operation_id, msf_session_id, session_type, target_host,
            target_port, via_exploit, via_payload, platform, arch, opened_at
        ))
        self.conn.commit()
        return cursor.lastrowid
    
    def close_msf_session(self, operation_id: int, msf_session_id: int) -> bool:
        """
        Mark a Metasploit session as closed.
        
        Args:
            operation_id: ID of the parent operation
            msf_session_id: Metasploit's session ID
            
        Returns:
            True if session was found and updated, False otherwise
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE msf_sessions SET
                is_active = 0,
                closed_at = CURRENT_TIMESTAMP
            WHERE operation_id = ? AND msf_session_id = ?
        """, (operation_id, msf_session_id))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def get_msf_sessions(self, operation_id: int = None, 
                         active_only: bool = False) -> List[Dict]:
        """Get Metasploit session history."""
        cursor = self.conn.cursor()
        
        where_clauses = []
        params = []
        
        if operation_id:
            where_clauses.append("operation_id = ?")
            params.append(operation_id)
        if active_only:
            where_clauses.append("is_active = 1")
        
        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        cursor.execute(f"""
            SELECT * FROM msf_sessions
            {where_sql}
            ORDER BY opened_at DESC
        """, params)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_operation_actions_chronological(self, operation_id: int) -> List[Dict]:
        """
        Get all actions (CLI commands and RPC actions) for an operation
        in chronological order by step number.
        
        Args:
            operation_id: ID of the operation
            
        Returns:
            List of actions sorted by step_number, with 'source' field
            indicating 'cli' or 'rpc'
        """
        import json
        cursor = self.conn.cursor()
        
        # Get CLI commands
        cursor.execute("""
            SELECT 
                id, step_number, 'cli' as source, command as action_detail,
                output, success as result_success, executed_at as timestamp
            FROM commands
            WHERE operation_id = ?
        """, (operation_id,))
        cli_actions = [dict(row) for row in cursor.fetchall()]
        
        # Get RPC actions
        cursor.execute("""
            SELECT 
                id, step_number, 'rpc' as source, 
                action_type || ':' || COALESCE(module_name, '') as action_detail,
                result_data as output, result_success, created_at as timestamp
            FROM rpc_actions
            WHERE operation_id = ?
        """, (operation_id,))
        rpc_actions = [dict(row) for row in cursor.fetchall()]
        
        # Combine and sort by step_number (None values go last)
        all_actions = cli_actions + rpc_actions
        all_actions.sort(key=lambda x: (x['step_number'] is None, x['step_number'] or 0))
        
        return all_actions

    # ==================== STATISTICS ====================
    
    def get_stats(self) -> Dict:
        """Get overall database statistics."""
        cursor = self.conn.cursor()
        
        stats = {}
        
        cursor.execute("SELECT COUNT(*) FROM targets")
        stats['total_targets'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM services")
        stats['total_services'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats['total_vulns'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM credentials WHERE valid = 1")
        stats['total_creds'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM operations")
        stats['total_operations'] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM loot")
        stats['total_loot'] = cursor.fetchone()[0]
        
        return stats
    
    # ==================== CLEANUP ====================
    
    def clear_target(self, ip: str):
        """Remove all data for a target."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM targets WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        
        if not row:
            return
        
        target_id = row['id']
        
        # Delete in order (foreign keys)
        cursor.execute("DELETE FROM commands WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM operations WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM loot WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM credentials WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM users WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM vulnerabilities WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM services WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM closed_ports WHERE target_id = ?", (target_id,))
        cursor.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        
        self.conn.commit()
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None


# Global database instance
_db: Optional[FragmentumDB] = None


def get_db(db_path: str = None) -> FragmentumDB:
    """Get or create the global database instance."""
    global _db
    if _db is None:
        _db = FragmentumDB(db_path)
    return _db


def reset_db():
    """Reset the global database instance."""
    global _db
    if _db:
        _db.close()
    _db = None
