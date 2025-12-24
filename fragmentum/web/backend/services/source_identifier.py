"""
Source Identifier module for detecting shell connection origins.

Requirements:
- 6.2: Attempt to identify source tool and target information automatically

This module provides pattern-based identification of shell connections
from various external tools like Metasploit, netcat, Cobalt Strike, etc.
"""

import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum


class SourceType(str, Enum):
    """Known source types for shell connections."""
    METASPLOIT = "metasploit"
    NETCAT = "netcat"
    COBALT_STRIKE = "cobalt_strike"
    EMPIRE = "empire"
    SOCAT = "socat"
    PYTHON_SHELL = "python_shell"
    BASH_SHELL = "bash_shell"
    PHP_SHELL = "php_shell"
    PERL_SHELL = "perl_shell"
    RUBY_SHELL = "ruby_shell"
    POWERSHELL = "powershell"
    CMD = "cmd"
    SHELL = "shell"  # Generic shell
    EXTERNAL = "external"  # Unknown external source


@dataclass
class SourceIdentification:
    """Result of source identification."""
    source: str
    confidence: float  # 0.0 to 1.0
    characteristics: Dict[str, Any]
    matched_patterns: List[str]


class SourceIdentifier:
    """
    Identifies the source tool of shell connections.
    
    Requirements 6.2: Attempt to identify source tool and target information automatically
    
    Uses pattern matching on initial connection data to identify:
    - The tool that created the shell (Metasploit, netcat, etc.)
    - Operating system of the target
    - Shell type (bash, sh, powershell, etc.)
    - Privilege level (root/admin or user)
    """
    
    # Pattern definitions with confidence weights
    # Higher weight = more confident identification
    TOOL_PATTERNS: Dict[str, List[Tuple[bytes, float]]] = {
        SourceType.METASPLOIT: [
            (rb"meterpreter", 0.95),
            (rb"Meterpreter", 0.95),
            (rb"msf\d?[>\s]", 0.90),
            (rb"PAYLOAD=", 0.80),
            (rb"stage\d", 0.70),
            (rb"msfvenom", 0.90),
            (rb"reverse_tcp", 0.75),
            (rb"bind_tcp", 0.75),
        ],
        SourceType.NETCAT: [
            (rb"GNU netcat", 0.95),
            (rb"ncat\s", 0.90),
            (rb"nc\s+-[elvp]", 0.85),
            (rb"Ncat:", 0.90),
        ],
        SourceType.COBALT_STRIKE: [
            (rb"beacon", 0.85),
            (rb"Beacon", 0.85),
            (rb"cobaltstrike", 0.95),
            (rb"cs_", 0.70),
        ],
        SourceType.EMPIRE: [
            (rb"empire", 0.85),
            (rb"Empire", 0.85),
            (rb"powershell.*-enc\s+[A-Za-z0-9+/=]+", 0.80),
            (rb"stager", 0.60),
        ],
        SourceType.SOCAT: [
            (rb"socat", 0.90),
            (rb"SOCAT", 0.90),
        ],
        SourceType.PYTHON_SHELL: [
            (rb"python.*-c.*socket", 0.85),
            (rb"import socket.*connect", 0.80),
            (rb"import pty.*spawn", 0.85),
            (rb"subprocess\.call.*bash", 0.75),
        ],
        SourceType.BASH_SHELL: [
            (rb"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", 0.90),
            (rb"bash\s+-i\s+>&", 0.85),
            (rb"exec\s+\d+<>/dev/tcp", 0.85),
            (rb"0<&\d+;exec\s+\d+<&0", 0.80),
        ],
        SourceType.PHP_SHELL: [
            (rb"<\?php.*fsockopen", 0.90),
            (rb"php\s+-r.*socket", 0.85),
            (rb"shell_exec.*nc\s", 0.75),
            (rb"proc_open", 0.70),
        ],
        SourceType.PERL_SHELL: [
            (rb"perl.*-e.*socket", 0.85),
            (rb"IO::Socket::INET", 0.90),
            (rb"use Socket;", 0.85),
        ],
        SourceType.RUBY_SHELL: [
            (rb"ruby.*-rsocket", 0.85),
            (rb"TCPSocket\.new", 0.90),
            (rb"TCPSocket\.open", 0.90),
        ],
        SourceType.POWERSHELL: [
            (rb"powershell", 0.80),
            (rb"pwsh", 0.80),
            (rb"PS\s+[A-Z]:\\", 0.85),
            (rb"\$client\s*=\s*New-Object", 0.80),
            (rb"System\.Net\.Sockets\.TCPClient", 0.90),
            (rb"Invoke-Expression", 0.70),
        ],
        SourceType.CMD: [
            (rb"Microsoft Windows", 0.85),
            (rb"cmd\.exe", 0.80),
            (rb"C:\\Windows\\system32>", 0.90),
            (rb"C:\\Users\\", 0.75),
        ],
    }
    
    # OS detection patterns
    OS_PATTERNS: Dict[str, List[Tuple[bytes, float]]] = {
        "linux": [
            (rb"Linux\s+\w+\s+\d+\.\d+", 0.95),
            (rb"ubuntu", 0.90),
            (rb"debian", 0.90),
            (rb"centos", 0.90),
            (rb"fedora", 0.90),
            (rb"redhat", 0.90),
            (rb"kali", 0.90),
            (rb"/bin/bash", 0.70),
            (rb"/bin/sh", 0.60),
        ],
        "windows": [
            (rb"Microsoft Windows", 0.95),
            (rb"Windows\s+\d+", 0.90),
            (rb"cmd\.exe", 0.85),
            (rb"C:\\", 0.80),
            (rb"powershell", 0.75),
        ],
        "macos": [
            (rb"Darwin", 0.95),
            (rb"macOS", 0.95),
            (rb"Mac OS X", 0.95),
            (rb"/usr/bin/osascript", 0.85),
        ],
        "bsd": [
            (rb"FreeBSD", 0.95),
            (rb"OpenBSD", 0.95),
            (rb"NetBSD", 0.95),
        ],
    }
    
    # Shell type patterns
    SHELL_PATTERNS: Dict[str, List[Tuple[bytes, float]]] = {
        "bash": [
            (rb"bash-\d+\.\d+", 0.95),
            (rb"/bin/bash", 0.85),
            (rb"GNU bash", 0.95),
        ],
        "sh": [
            (rb"/bin/sh", 0.80),
            (rb"sh-\d+\.\d+", 0.90),
        ],
        "zsh": [
            (rb"zsh", 0.90),
            (rb"/bin/zsh", 0.90),
        ],
        "fish": [
            (rb"fish", 0.85),
            (rb"/usr/bin/fish", 0.90),
        ],
        "powershell": [
            (rb"PowerShell", 0.95),
            (rb"pwsh", 0.90),
            (rb"PS\s+[A-Z]:\\", 0.90),
        ],
        "cmd": [
            (rb"cmd\.exe", 0.90),
            (rb"C:\\Windows\\system32>", 0.95),
        ],
    }
    
    # Privilege patterns
    PRIVILEGE_PATTERNS = {
        "root": [
            (rb"root@", 0.95),
            (rb"#\s*$", 0.70),
            (rb"uid=0", 0.95),
            (rb"euid=0", 0.95),
        ],
        "admin": [
            (rb"Administrator", 0.90),
            (rb"SYSTEM", 0.85),
            (rb"NT AUTHORITY\\SYSTEM", 0.95),
        ],
    }
    
    def __init__(self):
        """Initialize the source identifier."""
        pass
    
    def identify(self, data: bytes) -> SourceIdentification:
        """
        Identify the source of a shell connection from initial data.
        
        Args:
            data: Initial data bytes from the connection
            
        Returns:
            SourceIdentification with source, confidence, and characteristics
        """
        if not data:
            return SourceIdentification(
                source=SourceType.EXTERNAL,
                confidence=0.0,
                characteristics={},
                matched_patterns=[],
            )
        
        # Identify the tool
        source, tool_confidence, tool_patterns = self._identify_tool(data)
        
        # Detect characteristics
        characteristics = self._detect_characteristics(data)
        
        return SourceIdentification(
            source=source,
            confidence=tool_confidence,
            characteristics=characteristics,
            matched_patterns=tool_patterns,
        )
    
    def _identify_tool(self, data: bytes) -> Tuple[str, float, List[str]]:
        """
        Identify the tool that created the shell.
        
        Args:
            data: Initial data bytes
            
        Returns:
            Tuple of (source_name, confidence, matched_patterns)
        """
        best_source = SourceType.EXTERNAL
        best_confidence = 0.0
        matched_patterns = []
        
        for source_type, patterns in self.TOOL_PATTERNS.items():
            for pattern, confidence in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    matched_patterns.append(pattern.decode('utf-8', errors='replace'))
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_source = source_type
        
        # If no specific tool found, check for generic shell indicators
        if best_source == SourceType.EXTERNAL:
            shell_prompts = [
                (rb"[$#>]\s*$", 0.50),
                (rb"\w+@\w+[:\s]", 0.60),
            ]
            for pattern, confidence in shell_prompts:
                if re.search(pattern, data):
                    best_source = SourceType.SHELL
                    best_confidence = max(best_confidence, confidence)
                    matched_patterns.append(pattern.decode('utf-8', errors='replace'))
        
        return best_source, best_confidence, matched_patterns
    
    def _detect_characteristics(self, data: bytes) -> Dict[str, Any]:
        """
        Detect characteristics of the shell from initial data.
        
        Args:
            data: Initial data bytes
            
        Returns:
            Dictionary with detected characteristics
        """
        characteristics = {
            "has_prompt": False,
            "is_privileged": False,
            "privilege_type": None,
            "detected_os": None,
            "os_confidence": 0.0,
            "detected_shell": None,
            "shell_confidence": 0.0,
        }
        
        # Check for shell prompt
        if re.search(rb"[$#>]\s*$", data):
            characteristics["has_prompt"] = True
        
        # Detect privilege level
        for priv_type, patterns in self.PRIVILEGE_PATTERNS.items():
            for pattern, confidence in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    characteristics["is_privileged"] = True
                    characteristics["privilege_type"] = priv_type
                    break
            if characteristics["is_privileged"]:
                break
        
        # Detect OS
        for os_name, patterns in self.OS_PATTERNS.items():
            for pattern, confidence in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    if confidence > characteristics["os_confidence"]:
                        characteristics["detected_os"] = os_name
                        characteristics["os_confidence"] = confidence
        
        # Detect shell type
        for shell_name, patterns in self.SHELL_PATTERNS.items():
            for pattern, confidence in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    if confidence > characteristics["shell_confidence"]:
                        characteristics["detected_shell"] = shell_name
                        characteristics["shell_confidence"] = confidence
        
        return characteristics
    
    def get_source_display_name(self, source: str) -> str:
        """
        Get a human-readable display name for a source type.
        
        Args:
            source: The source identifier
            
        Returns:
            Human-readable display name
        """
        display_names = {
            SourceType.METASPLOIT: "Metasploit",
            SourceType.NETCAT: "Netcat",
            SourceType.COBALT_STRIKE: "Cobalt Strike",
            SourceType.EMPIRE: "Empire",
            SourceType.SOCAT: "Socat",
            SourceType.PYTHON_SHELL: "Python Shell",
            SourceType.BASH_SHELL: "Bash Shell",
            SourceType.PHP_SHELL: "PHP Shell",
            SourceType.PERL_SHELL: "Perl Shell",
            SourceType.RUBY_SHELL: "Ruby Shell",
            SourceType.POWERSHELL: "PowerShell",
            SourceType.CMD: "Windows CMD",
            SourceType.SHELL: "Shell",
            SourceType.EXTERNAL: "External",
        }
        return display_names.get(source, source.replace("_", " ").title())


# Global instance
_source_identifier: Optional[SourceIdentifier] = None


def get_source_identifier() -> SourceIdentifier:
    """Get the global source identifier instance."""
    global _source_identifier
    if _source_identifier is None:
        _source_identifier = SourceIdentifier()
    return _source_identifier
