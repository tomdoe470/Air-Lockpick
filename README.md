Air-Lockpick
=============

Herramienta de reconocimiento y soporte para ejercicios de red team sobre infraestructuras Wi-Fi.

## Objetivo

**Air-Lockpick** busca automatizar las primeras fases de reconocimiento sobre redes inalámbricas:

- **Detección de interfaces Wi-Fi** disponibles.
- **Verificación y activación del modo monitor** en la interfaz seleccionada.
- **Escaneo de todos los puntos de acceso** y recopilación de información básica.
- **Selección interactiva de un AP** por parte del usuario para análisis detallado.
- **Análisis profundo del AP**:
  - Fabricante y posible ISP/tecnología a partir de la MAC (OUI lookup).
  - Listado de clientes asociados.
  - Información básica de clientes según sus MAC.
  - Estado de WPS (si está activado, modos conocidos, flags relevantes).
  - **Recomendaciones** tácticas basadas en las características del AP y de los clientes.

> Nota: gran parte de estas capacidades requieren ejecutarse en un entorno tipo Linux (Kali, Parrot, Ubuntu) con herramientas como `airmon-ng` y `airodump-ng`, y con permisos de root. En Windows se recomienda usar WSL2 o una VM.

## Arquitectura propuesta

- **Lenguaje**: Python 3.
- **Modo de uso**: CLI interactiva.
- **Fuentes de datos principales**:
  - Salida de `iw`, `iwconfig`, `ip link` para detectar interfaces y estado.
  - `airmon-ng` para gestionar el modo monitor.
  - `airodump-ng` (formato CSV) para obtener APs y clientes.
  - Base de datos OUI (local o vía librería) para resolver fabricantes.

## Flujo básico (MVP)

1. Detectar interfaces Wi-Fi disponibles.
2. Preguntar al usuario qué interfaz usar.
3. Verificar si está en modo monitor; si no lo está, intentar activarlo.
4. Lanzar un escaneo corto con `airodump-ng` y parsear el CSV resultante.
5. Mostrar una lista de APs (BSSID, ESSID, canal, potencia, cifrado, etc.).
6. Preguntar al usuario qué AP quiere analizar.
7. Hacer un escaneo enfocado en ese AP para sacar:
   - Clientes asociados.
   - Más detalles de la red.
8. Resolver fabricantes de MAC (AP y clientes).
9. Generar un pequeño informe con:
   - Resumen técnico de la red.
   - Posibles ISP/tecnologías sugeridas por el OUI.
   - Estado WPS (si la herramienta lo puede detectar).
   - Recomendaciones de ataque / pruebas sugeridas.

## Estructura de proyecto (inicial)

- `air_lockpick/`
  - `__init__.py`
  - `main.py` — punto de entrada CLI.
  - `wifi_interfaces.py` — detección de interfaces y modo monitor.
  - `scanner.py` — integración con `airodump-ng` y parsing CSV.
  - `analysis.py` — lógica de análisis de AP/clientes y recomendaciones.
- `requirements.txt`

## Uso previsto (cuando el MVP esté listo)

```bash
sudo python -m air_lockpick
```

El programa:

- Te mostrará las interfaces Wi-Fi.
- Activará modo monitor si hace falta.
- Escaneará redes y te permitirá elegir una.
- Mostrará un informe básico del AP y sus clientes.

## Aviso legal

Air-Lockpick está pensado **exclusivamente para entornos controlados y con autorización explícita** (laboratorios, ejercicios de red team, entornos de prueba). El uso en redes de terceros sin permiso puede ser ilegal.

