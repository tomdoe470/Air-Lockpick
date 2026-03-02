import subprocess
from dataclasses import dataclass
from typing import List


@dataclass
class WifiInterface:
    name: str
    is_monitor: bool
    description: str | None = None


def _run_cmd(cmd: list[str]) -> str:
    """Ejecuta un comando y devuelve stdout como texto."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def list_wifi_interfaces() -> List[WifiInterface]:
    """
    Lista interfaces Wi-Fi conocidas.

    MVP: implementación muy simple basada en `iw dev` o `iwconfig`.
    En Windows/entornos sin estas herramientas devolverá una lista vacía.
    """
    try:
        out = _run_cmd(["iw", "dev"])
    except FileNotFoundError:
        return []

    interfaces: List[WifiInterface] = []
    current: dict[str, str] = {}

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            if "name" in current:
                interfaces.append(
                    WifiInterface(
                        name=current["name"],
                        is_monitor=current.get("type") == "monitor",
                        description=None,
                    )
                )
                current = {}
            current["name"] = line.split()[1]
        elif line.startswith("type "):
            current["type"] = line.split()[1]

    if "name" in current:
        interfaces.append(
            WifiInterface(
                name=current["name"],
                is_monitor=current.get("type") == "monitor",
                description=None,
            )
        )

    return interfaces


def ensure_monitor_mode(iface: WifiInterface) -> WifiInterface:
    """
    Verifica si la interfaz está en modo monitor y, si no, intenta activarlo.

    MVP: intenta usar `airmon-ng start <iface>`. En entornos sin airmon-ng
    no hará nada y devolverá la interfaz original.
    """
    if iface.is_monitor:
        return iface

    try:
        _run_cmd(["sudo", "airmon-ng", "start", iface.name])
    except FileNotFoundError:
        return iface

    # Re-leer las interfaces para ver si cambió el estado/nombre
    refreshed = list_wifi_interfaces()
    for it in refreshed:
        if it.name.startswith(iface.name):
            return it

    return iface

