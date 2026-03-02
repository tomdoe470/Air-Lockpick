from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.table import Table

from .wifi_interfaces import list_wifi_interfaces, ensure_monitor_mode
from .scanner import scan_access_points, scan_clients_for_ap
from .analysis import analyze_access_point


console = Console()


def _select_from_list(title: str, options: list[str]) -> Optional[int]:
    if not options:
        console.print(f"[bold red]{title}[/bold red]: no hay opciones disponibles.")
        return None

    console.print(f"\n[bold cyan]{title}[/bold cyan]")
    for idx, label in enumerate(options, start=1):
        console.print(f"  [yellow]{idx}[/yellow]. {label}")

    while True:
        raw = console.input("[green]Elige una opción (número, Enter para cancelar): [/green]").strip()
        if not raw:
            return None
        if not raw.isdigit():
            console.print("[red]Entrada no válida, debe ser un número.[/red]")
            continue
        choice = int(raw)
        if 1 <= choice <= len(options):
            return choice - 1
        console.print("[red]Opción fuera de rango.[/red]")


def run() -> None:
    console.print("[bold magenta]Air-Lockpick[/bold magenta] - Recon Wi-Fi para red team\n")

    interfaces = list_wifi_interfaces()
    if not interfaces:
        console.print(
            "[red]No se encontraron interfaces Wi-Fi (o no está disponible `iw`).[/red]\n"
            "Ejecuta esta herramienta en un entorno Linux con utilidades wireless instaladas."
        )
        return

    iface_labels = [
        f"{it.name} ({'monitor' if it.is_monitor else 'managed'})" for it in interfaces
    ]
    idx = _select_from_list("Selecciona la interfaz Wi-Fi", iface_labels)
    if idx is None:
        console.print("Cancelado por el usuario.")
        return

    iface = interfaces[idx]
    console.print(f"\nUsando interfaz [bold]{iface.name}[/bold].")
    iface = ensure_monitor_mode(iface)
    if not iface.is_monitor:
        console.print(
            "[red]No se pudo asegurar el modo monitor. Revisa manualmente con airmon-ng/iwconfig.[/red]"
        )
        # Se sigue igualmente, por si acaso.

    console.print("\n[bold]Escaneando redes cercanas (MVP / datos simulados)...[/bold]")
    aps = scan_access_points(iface.name)
    if not aps:
        console.print("[red]No se detectaron APs.[/red]")
        return

    ap_labels = [
        f"{ap.essid or '<oculta>'} | {ap.bssid} | ch {ap.channel} | {ap.encryption or '???'}"
        for ap in aps
    ]
    ap_idx = _select_from_list("Selecciona el AP a analizar", ap_labels)
    if ap_idx is None:
        console.print("Cancelado por el usuario.")
        return

    ap = aps[ap_idx]
    console.print(f"\nAnalizando AP [bold]{ap.essid}[/bold] ({ap.bssid})...\n")

    clients = scan_clients_for_ap(iface.name, ap)
    report = analyze_access_point(ap, clients)

    # Tabla del AP
    ap_table = Table(title="Punto de acceso")
    ap_table.add_column("Campo")
    ap_table.add_column("Valor")
    ap_table.add_row("ESSID", report.ap.essid)
    ap_table.add_row("BSSID", report.ap.bssid)
    ap_table.add_row("Canal", str(report.ap.channel))
    ap_table.add_row("Potencia", str(report.ap.power) if report.ap.power is not None else "N/D")
    ap_table.add_row("Cifrado", report.ap.encryption or "N/D")
    ap_table.add_row("Fabricante (OUI)", report.ap_info.vendor or "Desconocido")
    ap_table.add_row("WPS", report.wps_info or "N/D")
    console.print(ap_table)

    # Tabla de clientes
    client_table = Table(title="Clientes asociados")
    client_table.add_column("#")
    client_table.add_column("MAC")
    client_table.add_column("Fabricante")
    client_table.add_column("Notas")
    for idx_c, ci in enumerate(report.clients, start=1):
        client_table.add_row(
            str(idx_c),
            ci.mac,
            ci.vendor or "Desconocido",
            ci.notes or "",
        )
    console.print(client_table)

    console.print("\n[bold green]Recomendaciones iniciales:[/bold green]")
    for rec in report.recommendations:
        console.print(f"- {rec}")


if __name__ == "__main__":
    run()

