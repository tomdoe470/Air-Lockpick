from dataclasses import dataclass
from typing import List

from mac_vendor_lookup import MacLookup  # type: ignore[import]

from .scanner import AccessPoint, ClientStation


@dataclass
class DeviceInfo:
    mac: str
    vendor: str | None
    notes: str | None = None


@dataclass
class AccessPointReport:
    ap: AccessPoint
    ap_info: DeviceInfo
    clients: List[DeviceInfo]
    wps_info: str | None
    recommendations: List[str]


_mac_lookup = MacLookup()


def _safe_vendor_lookup(mac: str) -> str | None:
    try:
        return _mac_lookup.lookup(mac)
    except Exception:
        return None


def analyze_access_point(ap: AccessPoint, clients: List[ClientStation]) -> AccessPointReport:
    """
    Genera un informe de alto nivel sobre un AP y sus clientes.

    Aquí es donde se concentrará la lógica de:
    - identificación de fabricante/ISP probable,
    - interpretación del cifrado,
    - heurísticas sobre exposición, etc.
    """
    ap_vendor = _safe_vendor_lookup(ap.bssid)

    client_infos: List[DeviceInfo] = []
    for c in clients:
        vendor = _safe_vendor_lookup(c.mac)
        notes = None
        if c.power is not None and c.power > -50:
            notes = "Cliente muy cercano al AP (señal fuerte)."
        client_infos.append(
            DeviceInfo(
                mac=c.mac,
                vendor=vendor,
                notes=notes,
            )
        )

    # TODO: detección real de WPS (por ahora asumimos desconocido)
    wps_info = "Desconocido (se requiere integración con herramientas específicas de WPS)."

    recommendations: List[str] = []

    if ap.encryption and "WEP" in ap.encryption.upper():
        recommendations.append(
            "El AP usa WEP: muy débil. Considerar ataques de reinyección y crackeo de clave WEP."
        )
    elif ap.encryption and "WPA3" in ap.encryption.upper():
        recommendations.append(
            "El AP anuncia WPA3: enfocarse en clientes legacy o configuraciones mixtas WPA2/WPA3."
        )
    else:
        recommendations.append(
            "AP con WPA2: evaluar recolección de handshakes y ataques de diccionario/wordlist específicas del entorno."
        )

    if any(ci.vendor and "Android" in ci.vendor for ci in client_infos):
        recommendations.append(
            "Hay clientes Android: considerar ataques de ingeniería social y phishing Wi-Fi dirigidos."
        )

    recommendations.append(
        "Para WPS, usar herramientas como `wash`, `reaver`, `bully` o `onewps` para comprobar si está activo y en qué modo."
    )

    return AccessPointReport(
        ap=ap,
        ap_info=DeviceInfo(
            mac=ap.bssid,
            vendor=ap_vendor,
            notes=None,
        ),
        clients=client_infos,
        wps_info=wps_info,
        recommendations=recommendations,
    )

