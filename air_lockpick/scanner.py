from dataclasses import dataclass
from typing import List


@dataclass
class AccessPoint:
    bssid: str
    essid: str
    channel: int
    power: int | None
    encryption: str | None


@dataclass
class ClientStation:
    mac: str
    ap_bssid: str
    power: int | None


def scan_access_points(iface_name: str, timeout_seconds: int = 10) -> List[AccessPoint]:
    """
    Escanea redes Wi-Fi y devuelve una lista de APs.

    MVP: función "stub" que devuelve datos simulados si no se puede
    acceder a `airodump-ng`. Más adelante se puede implementar el
    lanzamiento de `airodump-ng --output-format csv` y parsear el CSV.
    """
    # TODO: integrar con airodump-ng y parsear CSV real.
    # Por ahora devolvemos un par de redes de ejemplo.
    return [
        AccessPoint(
            bssid="AA:BB:CC:DD:EE:01",
            essid="Red_Corporativa",
            channel=6,
            power=-45,
            encryption="WPA2",
        ),
        AccessPoint(
            bssid="AA:BB:CC:DD:EE:02",
            essid="Invitados",
            channel=11,
            power=-65,
            encryption="WPA2-Enterprise",
        ),
    ]


def scan_clients_for_ap(iface_name: str, ap: AccessPoint, timeout_seconds: int = 20) -> List[ClientStation]:
    """
    Escanea clientes asociados a un AP concreto.

    MVP: stub con datos simulados. En el futuro debe hacer un
    airodump-ng enfocado al BSSID y parsear el CSV para obtener
    estaciones.
    """
    return [
        ClientStation(
            mac="F0:DE:F1:23:45:67",
            ap_bssid=ap.bssid,
            power=-40,
        ),
        ClientStation(
            mac="10:9A:DD:11:22:33",
            ap_bssid=ap.bssid,
            power=-70,
        ),
    ]

