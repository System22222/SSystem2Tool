import sys, os, math, time, hashlib, zipfile, shutil, threading, tempfile, webbrowser, urllib.request
import ctypes, ssl, traceback, urllib.error, json
from collections import deque
from PySide6.QtCore import Qt, QTimer, QPointF, QRectF, QEvent, QObject, Signal
from PySide6.QtGui import (QIcon, QPainter, QPixmap, QColor, QPen, QFont, QMovie,
                           QBrush, QPolygonF, QPainterPath)
from PySide6.QtWidgets import (QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
                               QHBoxLayout, QProgressBar, QGridLayout, QStackedWidget,
                               QButtonGroup, QScrollArea, QFrame, QMessageBox, QMenu)

RED = QColor(255, 30, 50)


def res(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def tools_dir():
    d = os.path.join(base_dir(), "tools")
    os.makedirs(d, exist_ok=True)
    return d


# ======================= AJUSTES / IDIOMA / TEMAS =======================
SETTINGS = {"lang": "es", "theme": "red"}


def settings_path():
    return os.path.join(base_dir(), "settings.json")


def load_settings():
    try:
        with open(settings_path(), encoding="utf-8") as f:
            d = json.load(f)
        if d.get("lang") in ("es", "en"):
            SETTINGS["lang"] = d["lang"]
        if d.get("theme") in ("red", "eiffel", "blue", "unlimited"):
            SETTINGS["theme"] = d["theme"]
    except Exception:
        pass


def save_settings():
    try:
        with open(settings_path(), "w", encoding="utf-8") as f:
            json.dump(SETTINGS, f)
    except Exception:
        pass


def tr(es, en):
    return es if SETTINGS["lang"] == "es" else en


THEMES = {
    "red": dict(bg="fondo.jpg", accent="#ff1e32", hover="#ff4b5c", rgb=(255, 30, 50),
                overlay=(25, 0, 6, 150), border="rgba(200,20,40,170)", cardhov="rgba(120,0,18,150)",
                scroll="rgba(255,30,50,170)", tipbg="#140508"),
    "eiffel": dict(bg="eiffel.jpg", accent="#b44cff", hover="#d08aff", rgb=(180, 76, 255),
                   overlay=(14, 0, 28, 120), border="rgba(150,60,230,170)", cardhov="rgba(85,20,150,165)",
                   scroll="rgba(170,80,255,170)", tipbg="#12051f"),
    "blue": dict(bg="azul.jpg", accent="#2e8bff", hover="#6db0ff", rgb=(46, 139, 255),
                 overlay=(0, 6, 30, 100), border="rgba(40,120,230,170)", cardhov="rgba(10,55,160,165)",
                 scroll="rgba(50,140,255,170)", tipbg="#040b1c"),
    "unlimited": dict(bg="ilimitado.jpg", accent="#e8b64a", hover="#ffd884", rgb=(232, 182, 74),
                      overlay=(20, 0, 8, 95), border="rgba(210,160,60,170)", cardhov="rgba(130,20,40,170)",
                      scroll="rgba(232,182,74,170)", tipbg="#1a060b", card="rgba(10,6,8,95)", slogan=True),
}


def theme():
    return THEMES[SETTINGS["theme"]]


# ======================= DESCRIPCIONES EN ESPAÑOL =======================
DESC_ES = {
    'Parses prefetch extracting file info': 'Analiza prefetch y extrae información de los archivos',
    'Parses BAM forensic artefact': 'Analiza el artefacto forense BAM',
    'Parses NTFS USNJournal entries': 'Analiza las entradas del USN Journal de NTFS',
    'Detect fileless via eventlog + memdump': 'Detecta malware fileless mediante el registro de eventos + volcado de memoria',
    'Parses JAR prefetch, DcomLaunch strings, etc': 'Analiza prefetch de JAR, strings de DcomLaunch, etc.',
    'Rundll32/Regsvr32 prefetch analysis': 'Análisis de prefetch de Rundll32/Regsvr32',
    'Detects JNI/JVMTI memory injections': 'Detecta inyecciones en memoria JNI/JVMTI',
    'Analyzes DPS memory': 'Analiza la memoria de DPS',
    'Detects USB device history': 'Detecta el historial de dispositivos USB',
    'Parser UserAssist artifact': 'Analiza el artefacto UserAssist',
    'Strings + YARA + signatures scanner': 'Escáner de strings + YARA + firmas',
    'Detects which domain or website a PC has accessed, even in incognito mode. Mainly for cases where web-based mouse configurators are used, such as hub.atk.pro.': 'Detecta a qué dominio o sitio web accedió un PC, incluso en modo incógnito. Pensado sobre todo para casos donde se usan configuradores de mouse web, como hub.atk.pro.',
    'The already integrated console host history of PowerShell': 'El historial de consola de PowerShell ya integrado en Windows',
    'Windows Event Viewer used to view system, application, security, and error logs': 'Visor de eventos de Windows para ver registros del sistema, aplicaciones, seguridad y errores',
    'Detects deleted Journal': 'Detecta si se borró el Journal',
    'Analyzes kernel live dumps and RAM dumps, generating output folders to investigate bypass and evasion techniques': 'Analiza volcados live de kernel y de RAM, generando carpetas de salida para investigar técnicas de bypass y evasión',
    'A screenshare tool that scans the javaw.exe processes memory for known and unknown cheat strings': 'Herramienta de screenshare que escanea la memoria de los procesos javaw.exe en busca de strings de cheats conocidos y desconocidos',
    'Virtual machine detector.': 'Detector de máquinas virtuales.',
    'Automatically detects the running javaw.exe process and scans the mods currently loaded in memory.': 'Detecta automáticamente el proceso javaw.exe en ejecución y escanea los mods cargados en memoria.',
    'Forensic analysis tool for Minecraft screenshare anticheat. Detects cheat clients through RAM memory scanning (Javaw) and DNS cache analysis, with generic module detection.': 'Herramienta de análisis forense para screenshare anticheat de Minecraft. Detecta clientes de cheat mediante escaneo de memoria RAM (Javaw) y análisis de la caché DNS, con detección genérica de módulos.',
    'A Windows forensic tool that detects and removes common bypass techniques, restrictions, and anti-forensic manipulations from the registry, event logs, and file system.': 'Herramienta forense de Windows que detecta y elimina técnicas comunes de bypass, restricciones y manipulaciones anti-forenses del registro, los registros de eventos y el sistema de archivos.',
    'Scans files for cheat client signatures, suspicious behavioral patterns, Strings, PE imports, obfuscation artifacts, and injection techniques, with VirusTotal verification.': 'Escanea archivos en busca de firmas de clientes de cheat, patrones de comportamiento sospechosos, strings, imports PE, artefactos de ofuscación y técnicas de inyección, con verificación en VirusTotal.',
    'CMD script to analyze Minecraft mods and identify potential cheat clients.': 'Script CMD para analizar mods de Minecraft e identificar posibles clientes de cheat.',
    'Parses NTFS journal entries': 'Analiza las entradas del journal de NTFS',
    'Parses pcasvc with signatures + YARA': 'Analiza pcasvc con firmas + YARA',
    'Strings of processes, signatures + YARA': 'Strings de procesos, firmas + YARA',
    'Parses paths from .txt or .bin with signatures + YARA': 'Analiza rutas de .txt o .bin con firmas + YARA',
    'Execution via activitiescache.db + YARA': 'Ejecución vía activitiescache.db + YARA',
    'Gathers BAM deleted keys': 'Recopila las claves BAM eliminadas',
    'Parses prefetch with signatures + YARA': 'Analiza prefetch con firmas + YARA',
    'Reads LiveKernel dumps, custom keywords': 'Lee volcados LiveKernel, con palabras clave personalizadas',
    'BAM Artefact: signatures, paths + YARA': 'Artefacto BAM: firmas, rutas + YARA',
    'View Windows event logs': 'Ver los registros de eventos de Windows',
    'Monitor network usage': 'Monitorear el uso de red',
    'View browser download history': 'Ver el historial de descargas del navegador',
    'View NTFS alternate data streams': 'Ver los flujos de datos alternativos (ADS) de NTFS',
    'Manage USB devices': 'Administrar dispositivos USB',
    'View Open/Save dialog history': 'Ver el historial de los diálogos Abrir/Guardar',
    'List executed programs': 'Listar los programas ejecutados',
    'View scheduled tasks': 'Ver las tareas programadas',
    'View Windows Jump Lists': 'Ver las Jump Lists de Windows',
    'View Windows Prefetch files': 'Ver los archivos Prefetch de Windows',
    'Advanced Registry scanner': 'Escáner avanzado del Registro',
    'View ShellBags entries': 'Ver las entradas de ShellBags',
    'View recent Windows activities and events': 'Ver actividades y eventos recientes de Windows',
    'View browsing history from multiple web browsers': 'Ver el historial de navegación de varios navegadores',
    'Analyze application execution records': 'Analiza registros de ejecución de aplicaciones',
    'Inspect cached application compatibility entries': 'Inspecciona entradas en caché de compatibilidad de aplicaciones',
    'Search binary files for text patterns': 'Busca patrones de texto en archivos binarios',
    'Export Windows event records': 'Exporta registros de eventos de Windows',
    'Open documents and binary files': 'Abre documentos y archivos binarios',
    'Calculate file and directory hashes': 'Calcula hashes de archivos y carpetas',
    'Analyze application Jump Lists': 'Analiza las Jump Lists de aplicaciones',
    'Browse Jump List artifacts visually': 'Explora visualmente los artefactos de Jump Lists',
    'Analyze Windows shortcut metadata': 'Analiza metadatos de accesos directos de Windows',
    'Extract NTFS filesystem records': 'Extrae registros del sistema de archivos NTFS',
    'Explore filesystem records visually': 'Explora visualmente los registros del sistema de archivos',
    'Analyze cached program execution traces': 'Analiza rastros de ejecución de programas en caché',
    'Inspect deleted-file metadata': 'Inspecciona metadatos de archivos eliminados',
    'Parse legacy recent-file cache records': 'Analiza registros heredados de la caché de archivos recientes',
    'Search and export registry artifacts': 'Busca y exporta artefactos del registro',
    'Explore registry hives visually': 'Explora visualmente las colmenas del registro',
    'Replay registry transaction records': 'Reproduce registros de transacciones del registro',
    'Inspect application compatibility databases': 'Inspecciona bases de datos de compatibilidad de aplicaciones',
    'Export folder browsing artifacts': 'Exporta artefactos de navegación de carpetas',
    'Explore ShellBag records visually': 'Explora visualmente los registros de ShellBag',
    'Analyze SQLite evidence using maps': 'Analiza evidencia SQLite mediante mapas',
    'Export SRUM activity, network and energy records': 'Exporta registros SRUM de actividad, red y energía',
    'Analyze Windows user access records': 'Analiza registros de acceso de usuarios de Windows',
    'Review forensic CSV timelines': 'Revisa líneas de tiempo forenses en CSV',
    'Mount volume shadow copies': 'Monta copias de volumen en sombra',
    'Analyze Windows Timeline activity': 'Analiza la actividad de la Línea de tiempo de Windows',
    'Parses Amcache with YARA, SHA1 filtering and VirusTotal.': 'Analiza Amcache con YARA, filtrado SHA1 y VirusTotal.',
    'Examines BAM execution history and artifact tampering.': 'Examina el historial de ejecución de BAM y la manipulación del artefacto.',
    'Combines browser downloads with USN tracking and YARA.': 'Combina descargas del navegador con seguimiento USN y YARA.',
    'Combines browsing history and flags suspicious domains.': 'Combina el historial de navegación y marca dominios sospechosos.',
    'Reviews crash artifacts, modified files and clearing attempts.': 'Revisa artefactos de crashes, archivos modificados e intentos de borrado.',
    'Analyzes paths with YARA and USN tracking.': 'Analiza rutas con YARA y seguimiento USN.',
    'Cross-references USB records to flag suspicious devices.': 'Cruza registros USB para marcar dispositivos sospechosos.',
    'Captures kernel and user memory for string searches.': 'Captura memoria de kernel y de usuario para buscar strings.',
    'Filters USN records and detects journal tampering.': 'Filtra registros USN y detecta manipulación del journal.',
    'Examines MFT records, historical traces and alternate streams.': 'Examina registros MFT, rastros históricos y flujos alternativos.',
    'Collects PowerShell history and flags suspicious activity.': 'Recopila el historial de PowerShell y marca actividad sospechosa.',
    'Examines SRUM network usage, services and timestamps.': 'Examina el uso de red, servicios y marcas de tiempo de SRUM.',
    'Cross-references saved files and download timestamps.': 'Cruza archivos guardados con las marcas de tiempo de descargas.',
    'Analyzes Prefetch with signature checks and YARA.': 'Analiza Prefetch con verificación de firmas y YARA.',
    'Monitors competitive Rainbow Six Siege match integrity.': 'Monitorea la integridad de partidas competitivas de Rainbow Six Siege.',
    'Examines executable strings, entropy and VirusTotal results.': 'Examina strings de ejecutables, entropía y resultados de VirusTotal.',
    'Examines startup entries, journal changes and digital signatures.': 'Examina entradas de inicio, cambios en el journal y firmas digitales.',
    "detect.ac's all-in-one screenshare scanner. One click reads Prefetch, BAM, Amcache, SRUM, the USN Journal, the registry, event logs, Sysmon and Autoruns, then ranks what deserves a closer look. It also includes a built-in downloader for every detect.ac ++ tool.": 'Escáner de screenshare todo en uno de detect.ac. Con un clic lee Prefetch, BAM, Amcache, SRUM, el USN Journal, el registro, los registros de eventos, Sysmon y Autoruns, y ordena lo que merece una revisión más a fondo. Incluye también un descargador integrado de todas las tools ++ de detect.ac.',
    "Detects multiple threats against a Scheduled Task on a user's PC using a PowerShell script.": 'Detecta múltiples amenazas contra una Tarea Programada en el PC del usuario mediante un script de PowerShell.',
    'Detects multiple threats against a SS on a users PC': 'Detecta múltiples amenazas contra una SS en el PC del usuario',
    'Detects enabled and disabled services including their start up time and how they are running letting us enable them or disable them.': 'Detecta servicios habilitados y deshabilitados, incluyendo su hora de inicio y cómo se ejecutan, permitiendo habilitarlos o deshabilitarlos.',
    "Detects Doomsday Client on the user's PC.": 'Detecta el cliente Doomsday en el PC del usuario.',
    'Fast runable script to detect DoomsDay client on a users PC': 'Script rápido y ejecutable para detectar el cliente DoomsDay en el PC del usuario',
    'Detects active VPN/Proxy active on the users PC.': 'Detecta VPN/Proxy activos en el PC del usuario.',
    'Kill recording processes (or atleast try to)': 'Cierra los procesos de grabación (o al menos lo intenta)',
    'Checks the mods in the folder you indicate and tells you if they are verified or not. It also checks suspicious strings.': 'Revisa los mods de la carpeta que indiques y te dice si están verificados o no. También revisa strings sospechosos.',
    'Detects multiple mouse macro options and opened software': 'Detecta varias opciones de macros de mouse y software abierto',
    'Check certain services and processes: status, uptime, suspended threads and other additional data.': 'Revisa ciertos servicios y procesos: estado, tiempo activo, hilos suspendidos y otros datos adicionales.',
    'A script almost identical to RedLotusBam, but with additional information. You will be able to view the Bam Entries.': 'Un script casi idéntico a RedLotusBam, pero con información adicional. Podrás ver las entradas de BAM.',
    'Connects to the live javaw.exe and dumps all class loaders + the classes each one loaded. Discovery tool for class-level injection.': 'Se conecta al javaw.exe en vivo y vuelca todos los class loaders + las clases que cargó cada uno. Herramienta de descubrimiento para inyección a nivel de clases.',
    'Runs YarpLetapStan mod analyzer v6.0': 'Ejecuta el analizador de mods YarpLetapStan v6.0',
    'Run Nicc/Services-checker from GitHub': 'Ejecuta Nicc/Services-checker desde GitHub',
    'Enumerates all system volumes (with letter, without letter and RAW).': 'Enumera todos los volúmenes del sistema (con letra, sin letra y RAW).',
    'Analyzes Prefetch Integrity for Bypass Attempts': 'Analiza la integridad de Prefetch en busca de intentos de bypass',
    'Gets the actual Java/Javaw processes and inspects the CommandLine of each one.': 'Obtiene los procesos Java/Javaw actuales e inspecciona la línea de comandos de cada uno.',
    'Detects classes that have been loaded outside the conventional folders like mods, libraries, processed mods, etc.': 'Detecta clases cargadas fuera de las carpetas convencionales como mods, libraries, processed mods, etc.',
    'Verifies paths of files saved in a .txt and tells you if the file exists there and if it has a signature.': 'Verifica las rutas de archivos guardadas en un .txt y te dice si el archivo existe ahí y si tiene firma.',
    'BAM Parser but in a script made by spokwn': 'BAM Parser en formato script, hecho por spokwn',
    'Locate .jar files with detailed checks (download page in browser)': 'Localiza archivos .jar con comprobaciones detalladas (abre la página de descarga en el navegador)',
    'Luyten Java decompiler (put Luyten.exe in tools/other)': 'Decompilador de Java Luyten (pon Luyten.exe en tools/other)',
    'Everything search engine': 'Motor de búsqueda Everything',
    'A highly powerful, multipurpose tool that helps you monitor system resources, debug software, and detect malware. Makes accessing services and processes very easy.': 'Herramienta muy potente y multipropósito para monitorear recursos del sistema, depurar software y detectar malware. Facilita mucho el acceso a servicios y procesos.',
    'Automated macro scanner for users doing SS.': 'Escáner automático de macros para quien hace SS.',
    'VirusTotal aggregates many antivirus products and online scan engines': 'VirusTotal reúne muchos antivirus y motores de análisis en línea',
    'Scan a users browser for malicious cheat client website visits / tells you if they downloaded a cheat client from that website': 'Escanea el navegador del usuario en busca de visitas a sitios maliciosos de clientes de cheat / te dice si descargó un cliente de cheat desde ese sitio',
    'Strings Checker (put PJ Cheat Scanner Lite.exe in tools/other)': 'Verificador de strings (pon PJ Cheat Scanner Lite.exe en tools/other)',
    'Lafferr Java Library Analyzer (put Java Library Analizer.exe in tools/other)': 'Analizador de librerías Java de Lafferr (pon Java Library Analizer.exe en tools/other)',
    'Siege is an automatic scan tool aimed mainly at Minecraft screenshares.': 'Siege es una herramienta de escaneo automático pensada sobre todo para screenshares de Minecraft.',
    'Detects and manages enabled/disabled services (script from lilith-ps).': 'Detecta y administra servicios habilitados/deshabilitados (script de lilith-ps).',
    'Lists the files in the Recycle Bin with their date and time.': 'Lista los archivos de la Papelera de reciclaje con su fecha y hora.',
    'Checks the services on the PC (script from lilith-ps).': 'Revisa los servicios del PC (script de lilith-ps).',
    'The .NET Desktop Runtime enables you to run existing Windows desktop applications.': 'El .NET Desktop Runtime permite ejecutar aplicaciones de escritorio de Windows existentes.',
    'Runtime library and compiler toolset used by Microsoft to build, run, and execute C++ applications.': 'Biblioteca de runtime y conjunto de herramientas de compilación de Microsoft para construir y ejecutar aplicaciones C++.',
    'Designed to run, develop, and manage robust, object-oriented applications on Windows.': 'Diseñado para ejecutar, desarrollar y administrar aplicaciones robustas orientadas a objetos en Windows.',
}


def desc_tr(d):
    return DESC_ES.get(d, d) if SETTINGS["lang"] == "es" else d


def norm(t):
    return "".join(c for c in t.lower() if c.isalnum())


# ======================= CATÁLOGO =======================
# kind: exe | installer | zip | zipcli | ps1 | cmd | embed | native | browser | manual
def T(name, desc, path=None, url=None, sha=None, kind="exe", cmd=None):
    return dict(name=name, desc=desc, path=path, url=url, sha=sha, kind=kind, cmd=cmd)


GH = "https://github.com/"
DET = GH + "detect-ac/Detect.ac-Free-Tools/releases/download/FreeTools/"


def NS(name, desc, slug, exe=None):
    return T(name, desc, exe or name + ".exe", f"https://www.nirsoft.net/utils/{slug}.zip", kind="zip")


def EZ(name, desc, zipname, exe, cli):
    base = "https://download.ericzimmermanstools.com/"
    url = base + ("hasher.zip" if zipname == "Hasher" else f"net9/{zipname}.zip")
    return T(name, desc, exe, url, kind="zipcli" if cli else "zip")


def PS(cmd):  # script remoto que se ejecuta con irm | iex
    return cmd


JDD = """Write-Host 'Time Changed Scanning...' -ForegroundColor Yellow
try { Get-EventLog -LogName Security -InstanceId 4616 -ErrorAction Stop | Select -ExpandProperty TimeGenerated } catch { Write-Host 'Nothing found' }
Write-Host ''
Write-Host 'Journal Deleted logs scanning...' -ForegroundColor Yellow
Write-Host ''
try { Get-WinEvent -FilterHashtable @{LogName='Application'; Id=3079} -ErrorAction Stop | Select-Object -ExpandProperty TimeCreated } catch { Write-Host 'Nothing found...' }
"""

VPN = """$ErrorActionPreference = 'Stop'
$ip = (Invoke-WebRequest -UseBasicParsing 'https://ifconfig.me/ip').Content.Trim()
$result = Invoke-RestMethod -Uri "https://proxycheck.io/v2/${ip}?vpn=1&asn=1"
$isProxy = $false
if ($result.PSObject.Properties.Name -contains $ip) { $isProxy = ($result.$ip.proxy -eq 'yes') }
Write-Host "IP consultada: $ip"
Write-Host "VPN/Proxy detectado: $isProxy"
"""

TABS = [
    ("orbdiff", "Orbdiff/Others", [
        T("PrefetchView++", "Parses prefetch extracting file info", "PrefetchView++.exe",
          GH + "Orbdiff/PrefetchView/releases/download/v1.6.8/pv%2B%2B.exe",
          "4a759585a6f37f96f6aefa72db7f2ad79d607d682523e6f30ea259cbeb42c567"),
        T("BAMReveal", "Parses BAM forensic artefact", "BAMReveal.exe",
          GH + "Orbdiff/BAMReveal/releases/download/v1.3.1/BAMReveal.exe",
          "4857fabf9c7ab1e44c59af5767f39b17686d8aae1098372c454e0c0ffa4550ac"),
        T("JournalParser", "Parses NTFS USNJournal entries", "JournalParser.exe",
          GH + "Orbdiff/JournalParser/releases/download/v1.2/JournalParser.exe",
          "8195c6237c41e0deb6783e151f0ec37c93830b7c730e2c98d67b1c0c1e3b7657"),
        T("Fileless", "Detect fileless via eventlog + memdump", "Fileless.exe",
          GH + "Orbdiff/Fileless/releases/download/v1.3/fileless.exe",
          "245929075877337ec4565160ea68a2afa3e5f7732f0087ddeffef43dc43afad4"),
        T("JARParser", "Parses JAR prefetch, DcomLaunch strings, etc", "JARParser.exe",
          GH + "Orbdiff/JARParser/releases/download/v1.2/JARParser.exe",
          "68cd2b0427f9fb48f68141917f2b1eac6824f7f8b59ccea708052246437da736"),
        T("PFTrace", "Rundll32/Regsvr32 prefetch analysis", "PFTrace.exe",
          GH + "Orbdiff/PFTrace/releases/download/v1.0.1/PFTrace.exe",
          "c0d8a21406d6c7cb1a5a50f288af70d833a7c065fa0528819d322c9efec02efc"),
        T("InjGen", "Detects JNI/JVMTI memory injections", "InjGen.exe",
          GH + "Orbdiff/InjGen/releases/download/fork/InjGen.exe",
          "226ebb238f0bbce73461ed28820d2f8eee55f8bbd5aefaa83dc2cff641e818c0"),
        T("DPS-Analyzer", "Analyzes DPS memory", "DPS-Analyzer.exe",
          GH + "Orbdiff/DPS-Analyzer/releases/download/v1.1/dpsanalyzer.exe",
          "20128c5dd2b9209873b5a631d3883507853ab0e6fba362b89b93870735ad3285"),
        T("USBDetector", "Detects USB device history", "USBDetector.exe",
          GH + "Orbdiff/USBDetector/releases/download/v1.1/USBDetector.exe",
          "caa6440b90c49163127d308594fff1c0cb26c26f8d0f43ab6e5a74e888dd971e"),
        T("UserAssistView", "Parser UserAssist artifact", "UserAssistView.exe",
          GH + "Orbdiff/UserAssistView/releases/download/v1.0/UserAssistView.exe",
          "65eed4536f1aa21fedd3e92ba32b9ef3682fcaf065d5c61e1239c6b7bf974c33"),
        T("StringsParser", "Strings + YARA + signatures scanner", "StringsParser.exe",
          GH + "Orbdiff/StringsParser/releases/download/v1.2.1b/stringsparser.1.2.1b.exe",
          "0453ba458b362ccfcfa502cef1c20d1ffb73c65cc0dfed1bba6b125d33e54fd2"),
        T("Web Hollowing", "Detects which domain or website a PC has accessed, even in incognito mode. "
          "Mainly for cases where web-based mouse configurators are used, such as hub.atk.pro.",
          "web.hollowing.exe", GH + "Orbdiff/WebHollowing/releases/download/v1.0/web.hollowing.exe"),
        T("ConsoleHostHistory", "The already integrated console host history of PowerShell", kind="native",
          cmd='powershell -NoLogo -NoProfile -Command "Get-Content (Get-PSReadLineOption).HistorySavePath"'),
        T("Eventvwr", "Windows Event Viewer used to view system, application, security, and error logs",
          kind="native", cmd="eventvwr.exe"),
        T("Journal Deleted Detector", "Detects deleted Journal", kind="embed", cmd=JDD),
        T("MarsPixelDumpAnalyzer", "Analyzes kernel live dumps and RAM dumps, generating output folders to "
          "investigate bypass and evasion techniques", "MarsPixelDumpAnalyzer.exe",
          GH + "zedoonvm1/MarsPixelDumpAnalyzer/releases/download/Dev/MarsPixelDumpAnalyzer.exe"),
        T("P1AE Scanner", "A screenshare tool that scans the javaw.exe processes memory for known and unknown "
          "cheat strings", "P1AE.Javaw.exe", GH + "p1aegg/javaw/releases/download/v1.12/P1AE.Javaw.exe",
          "f20057ba35dd1cbb2750e43b728fdb108a1fd3d93aed4ddff9a7e05c0f26fb76"),
        T("VMAware", "Virtual machine detector.", "vmaware32.exe",
          GH + "NotRequiem/VMAware/releases/download/v2.8.2/vmaware32.exe",
          "131a13eac73b8d34d36ef84c2b8192fef0bc1075b58ba3182e314685eb9769df"),
        T("RedLotus Mod Analyzer", "Automatically detects the running javaw.exe process and scans the mods "
          "currently loaded in memory.", "RedLotusModAnalyzer.exe",
          GH + "ItzIceHere/RedLotus-Mod-Analyzer/releases/download/RL/RedLotusModAnalyzer.exe",
          "4b7af53b5407595abb8969e6bfe1dd6eba85553e541a26697ae1230a4561e853"),
    ]),
    ("meow", "MeowTonynoh", [
        T("Meow Client Fucker", "Forensic analysis tool for Minecraft screenshare anticheat. Detects cheat clients "
          "through RAM memory scanning (Javaw) and DNS cache analysis, with generic module detection.",
          "MeowClientFucker.exe", GH + "MeowTonynoh/MeowClientFucker/releases/download/V1.1/MeowClientFucker.exe",
          "4afce4998dc5a336a6c8a503869bf9331ad2dffae125f10f7d4debfd3761bd73"),
        T("Meow Resolver", "A Windows forensic tool that detects and removes common bypass techniques, "
          "restrictions, and anti-forensic manipulations from the registry, event logs, and file system.",
          "MeowResolver.exe", GH + "MeowTonynoh/MeowResolver/releases/download/v.1.1/MeowResolver.exe",
          "cfbb52658b64c4b520e9d3d271e4622f464febf295043a0127e34c07c0fec7e1"),
        T("Meow Imports Checker", "Scans files for cheat client signatures, suspicious behavioral patterns, "
          "Strings, PE imports, obfuscation artifacts, and injection techniques, with VirusTotal verification.",
          "MeowImportsChecker.exe",
          GH + "MeowTonynoh/MeowImportsChecker/releases/download/MeowImportsChecker/MeowImportsChecker.exe",
          "33b5ab7cba9111f8b43c07c9b777010c30c7e14de46d275671a486ef9606a1a3"),
        T("Meow Mod Analyzer", "CMD script to analyze Minecraft mods and identify potential cheat clients.",
          "MeowModAnalyzer.ps1",
          "https://raw.githubusercontent.com/MeowTonynoh/MeowModAnalyzer/5221bfd6ae78b9dd1d3ce1057ee46cc83da3deff/MeowModAnalyzer.ps1",
          "86e85fe808242e784ab26236e70ac25baa67adfb1f01dc838afb6e7da43c2bfd", kind="ps1"),
    ]),
    ("spokwn", "Spokwn", [
        T("JournalTrace", "Parses NTFS journal entries", "JournalTrace.exe",
          GH + "spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe"),
        T("PcaSvcExecuted", "Parses pcasvc with signatures + YARA", "PcaSvcExecuted.exe",
          GH + "spokwn/pcasvc-executed/releases/download/v0.8.7/PcaSvcExecuted.exe"),
        T("ProcessParser", "Strings of processes, signatures + YARA", "ProcessParser.exe",
          GH + "spokwn/process-parser/releases/download/v0.5.5/ProcessParser.exe"),
        T("PathsParser", "Parses paths from .txt or .bin with signatures + YARA", "PathsParser.exe",
          GH + "spokwn/PathsParser/releases/download/v1.2/PathsParser.exe"),
        T("ActivitiesCache", "Execution via activitiescache.db + YARA", "ActivitiesCacheParser.exe",
          GH + "spokwn/ActivitiesCache-execution/releases/download/v0.6.5/ActivitiesCacheParser.exe"),
        T("BAMDeletedKeys", "Gathers BAM deleted keys", "BamDeletedKeys.exe",
          GH + "spokwn/BamDeletedKeys/releases/download/v1.0/BamDeletedKeys.exe"),
        T("PrefetchParser", "Parses prefetch with signatures + YARA", "PrefetchParser.exe",
          GH + "spokwn/prefetch-parser/releases/download/v1.5.5/PrefetchParser.exe"),
        T("KernelDumpTool", "Reads LiveKernel dumps, custom keywords", "KernelLiveDumpTool.exe",
          GH + "spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe",
          "b28ea771595d1a020ca04af2bed7008b9e6a65bb23ac9fe385aaa3341b21af9e"),
        T("BAMParser", "BAM Artefact: signatures, paths + YARA", "BAMParser.exe",
          GH + "spokwn/BAM-parser/releases/download/v1.2.9/BAMParser.exe"),
    ]),
    ("nirsoft", "NirSoft", [
        NS("FullEventLogView", "View Windows event logs", "fulleventlogview-x64"),
        NS("NetworkUsageView", "Monitor network usage", "networkusageview-x64"),
        NS("BrowserDownloadsView", "View browser download history", "browserdownloadsview-x64"),
        NS("AlternateStreamView", "View NTFS alternate data streams", "alternatestreamview-x64"),
        NS("USBDeview", "Manage USB devices", "usbdeview-x64"),
        NS("OpenSaveFilesView", "View Open/Save dialog history", "opensavefilesview-x64"),
        NS("ExecutedProgramsList", "List executed programs", "executedprogramslist"),
        NS("TaskSchedulerView", "View scheduled tasks", "taskschedulerview-x64"),
        NS("JumpListsView", "View Windows Jump Lists", "jumplistsview"),
        NS("WinPrefetchView", "View Windows Prefetch files", "winprefetchview-x64"),
        NS("RegScanner", "Advanced Registry scanner", "regscanner-x64"),
        NS("ShellBagsView", "View ShellBags entries", "shellbagsview"),
        NS("LastActivityView", "View recent Windows activities and events", "lastactivityview"),
        NS("BrowsingHistoryView", "View browsing history from multiple web browsers", "browsinghistoryview-x64"),
    ]),
    ("ericzimmerman", "Eric Zimmerman", [
        EZ("AmcacheParser", "Analyze application execution records", "AmcacheParser", "AmcacheParser.exe", True),
        EZ("AppCompatCacheParser", "Inspect cached application compatibility entries", "AppCompatCacheParser", "AppCompatCacheParser.exe", True),
        EZ("bstrings", "Search binary files for text patterns", "bstrings", "bstrings.exe", True),
        EZ("EvtxECmd", "Export Windows event records", "EvtxECmd", "EvtxECmd.exe", True),
        EZ("EZViewer", "Open documents and binary files", "EZViewer", "EZViewer.exe", False),
        EZ("Hasher", "Calculate file and directory hashes", "Hasher", "Hasher.exe", False),
        EZ("JLECmd", "Analyze application Jump Lists", "JLECmd", "JLECmd.exe", True),
        EZ("JumpList Explorer", "Browse Jump List artifacts visually", "JumpListExplorer", "JumpListExplorer.exe", False),
        EZ("LECmd", "Analyze Windows shortcut metadata", "LECmd", "LECmd.exe", True),
        EZ("MFTECmd", "Extract NTFS filesystem records", "MFTECmd", "MFTECmd.exe", True),
        EZ("MFTExplorer", "Explore filesystem records visually", "MFTExplorer", "MFTExplorer.exe", False),
        EZ("PECmd", "Analyze cached program execution traces", "PECmd", "PECmd.exe", True),
        EZ("RBCmd", "Inspect deleted-file metadata", "RBCmd", "RBCmd.exe", True),
        EZ("RecentFileCacheParser", "Parse legacy recent-file cache records", "RecentFileCacheParser", "RecentFileCacheParser.exe", True),
        EZ("RECmd", "Search and export registry artifacts", "RECmd", "RECmd.exe", True),
        EZ("Registry Explorer", "Explore registry hives visually", "RegistryExplorer", "RegistryExplorer.exe", False),
        EZ("RLA", "Replay registry transaction records", "rla", "rla.exe", True),
        EZ("SDB Explorer", "Inspect application compatibility databases", "SDBExplorer", "SDBExplorer.exe", False),
        EZ("SBECmd", "Export folder browsing artifacts", "SBECmd", "SBECmd.exe", True),
        EZ("ShellBags Explorer", "Explore ShellBag records visually", "ShellBagsExplorer", "ShellBagsExplorer.exe", False),
        EZ("SQLECmd", "Analyze SQLite evidence using maps", "SQLECmd", "SQLECmd.exe", True),
        EZ("SrumECmd", "Export SRUM activity, network and energy records", "SrumECmd", "SrumECmd.exe", True),
        EZ("SumECmd", "Analyze Windows user access records", "SumECmd", "SumECmd.exe", True),
        EZ("Timeline Explorer", "Review forensic CSV timelines", "TimelineExplorer", "TimelineExplorer.exe", False),
        EZ("VSCMount", "Mount volume shadow copies", "VSCMount", "VSCMount.exe", True),
        EZ("WxTCmd", "Analyze Windows Timeline activity", "WxTCmd", "WxTCmd.exe", True),
    ]),
    ("detectac", "Detect.ac", [
        T("AmCacheParser++", "Parses Amcache with YARA, SHA1 filtering and VirusTotal.", "AmcacheParser++.exe",
          DET + "AmcacheParser%2B%2B.exe", "4f6070e0a5570614f6b521835a4933440203adf7c80889a0b890b6f498255a80"),
        T("BamParser++", "Examines BAM execution history and artifact tampering.", "BamParser++.exe",
          DET + "BamParser%2B%2B.exe", "234a7c8eb1e1d19b037c70ad17baf621231d21fc655f4af72fe5fbebfc4749ec"),
        T("BrowserDownloadsView++", "Combines browser downloads with USN tracking and YARA.", "BrowserDownloadsView++.exe",
          DET + "BrowserDownloadsView%2B%2B.exe", "d32118630dfc8fb2bbbd700ed480285a61fd6bc787781d24d26573d6fb5884a6"),
        T("BrowsingHistoryView++", "Combines browsing history and flags suspicious domains.", "BrowsingHistoryView++.exe",
          DET + "BrowsingHistoryView%2B%2B.exe", "32bc3c4c445534925cf87014d403518a4c5f02af3cade288b450c2ab45ed5420"),
        T("CrashedFileViewer++", "Reviews crash artifacts, modified files and clearing attempts.", "CrashedFileViewer++.exe",
          DET + "CrashedFileViewer%2B%2B.exe", "491d683d3a78fbc0e989b5fb7762c53bd3d1038fa0a1f2d1c28cc67ba6f41e0c"),
        T("PathsParser++", "Analyzes paths with YARA and USN tracking.", "PathsParser++.exe",
          DET + "PathsParser%2B%2B.exe", "446b9909c74511d2f189f7a4f6f0a56a2606bdb5d620e43c0158e58b27a2ebb3"),
        T("USB Deview++", "Cross-references USB records to flag suspicious devices.", "USBDeview++.exe",
          DET + "USBDeview%2B%2B.exe", "93db1057f382ac3be2cf4a38bfaa4f8d7d6b851567e9381c0ff725623f747abf"),
        T("KernelLiveDump++", "Captures kernel and user memory for string searches.", "KernelLiveDump++.exe",
          DET + "KernelLiveDump%2B%2B.exe", "00e6efe19e39e1499cdeaecf4ad681f0b79859df12876ef90b0f27215b33d73a"),
        T("JournalTrace++", "Filters USN records and detects journal tampering.", "JournalTrace++.exe",
          DET + "JournalTrace%2B%2B.exe", "bb4354fe78f7417ee4026f0050f6773206c6996d78ef305fc6c5bd42d3cba92f"),
        T("MFTExplorer++", "Examines MFT records, historical traces and alternate streams.", "MFTExplorer++.exe",
          DET + "MFTExplorer%2B%2B.exe", "2a1ca5d90ba0bb69b90f10f23daae1a1d3c12d837d2d220ffe2ae8ce0bef9a75"),
        T("PowershellParser++", "Collects PowerShell history and flags suspicious activity.", "PowerShellParser++.exe",
          DET + "PowerShellParser%2B%2B.exe", "2b6c5f5b0f7c5415ea6ce343c9274a0fa28b26cdecfa990c93ff8fe366a0b94d"),
        T("SRUMExplorer++", "Examines SRUM network usage, services and timestamps.", "SRUMExplorer++.exe",
          DET + "SRUMExplorer%2B%2B.exe", "babbc35fa3643884d257fde457a4120556c00c0d08526b5c93a4e820f0616713"),
        T("SavedFilesViewer++", "Cross-references saved files and download timestamps.", "SavedFilesViewer++.exe",
          DET + "SavedFilesViewer%2B%2B.exe", "ea68e026515f3215b127367a52499c0f771dc627f709d14b00036e123895b54c"),
        T("WinPrefetchView++", "Analyzes Prefetch with signature checks and YARA.", "WinPrefetchView++.exe",
          DET + "WinPrefetchView%2B%2B.exe", "d00d9d3f9ad5c6dd9cd05850aab57d9835fdd1fddba54f6d5f7692c9d959eb56"),
        T("MOSS-2.0", "Monitors competitive Rainbow Six Siege match integrity.", "MOSS-2.0.exe",
          GH + "detect-ac/MOSS-2.0/releases/download/MOSS-2.0/MOSS-2.0.exe"),
        T("StringExplorer++", "Examines executable strings, entropy and VirusTotal results.", "StringExplorer++.exe",
          DET + "StringExplorer%2B%2B.exe", "ce3e4cc32f21d9f1a6a4423cf03c41ef8660adbdc18c14d43c71d1912868f236"),
        T("Autoruns++", "Examines startup entries, journal changes and digital signatures.", "Autoruns++.exe",
          DET + "Autoruns%2B%2B.exe", "79adbd44f89b86eda347b583a25275e6a5ad9d4c5ccd9ead31ecf1e0b6545458"),
        T("Collector++", "detect.ac's all-in-one screenshare scanner. One click reads Prefetch, BAM, Amcache, SRUM, "
          "the USN Journal, the registry, event logs, Sysmon and Autoruns, then ranks what deserves a closer look. "
          "It also includes a built-in downloader for every detect.ac ++ tool.", "Collector++.exe",
          DET + "Collector%2B%2B.exe"),
    ]),
    ("scripts", "Scripts", [
        T("AguaScript", "Detects multiple threats against a Scheduled Task on a user's PC using a PowerShell script.",
          "AguaScript.ps1",
          "https://raw.githubusercontent.com/AguaConGas17/Powershells/86e2634d54715d9275f1f819351d1ed64bbb5790/aguascript.ps1",
          "e0df4a0ff0dd8f992ccc0f4401a3fa1550b6b19739517ee6a48522fa71e3d685", kind="ps1"),
        T("Lilith Script", "Detects multiple threats against a SS on a users PC", kind="cmd",
          cmd="""powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/inkenal/rbw-SS-ps/refs/heads/main/Services.ps1')\""""),
        T("Lilith Services Enabler", "Detects enabled and disabled services including their start up time and how "
          "they are running letting us enable them or disable them.", "Service-Enabler.ps1",
          "https://raw.githubusercontent.com/praiselily/lilith-ps/89a9f9029efbb204665c0dae3a2e40d8d4d6ea81/Service-Enabler.ps1",
          "359ff89de147527b2326af558f04b4cd9170e16bb2055354e2ecd7e74d36d236", kind="ps1"),
        T("Real Doomsday Detector", "Detects Doomsday Client on the user's PC.", kind="cmd",
          cmd="""powershell -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/reala1-staff/DoomsdayScannerModified/refs/heads/main/Doomsday-scannerv3.ps1')\""""),
        T("Lilith DoomsDay Finder", "Fast runable script to detect DoomsDay client on a users PC", kind="cmd",
          cmd="""powershell -Command "Set-ExecutionPolicy Bypass -Scope Process; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/DoomsdayFinder.ps1')\""""),
        T("VPN Detector", "Detects active VPN/Proxy active on the users PC.", kind="embed", cmd=VPN),
        T("RecordingKiller", "Kill recording processes (or atleast try to)", "RecordingKiller.ps1",
          "https://raw.githubusercontent.com/Orbdiff/powershell/7f962e60c818cfb049b46a9f86907a36b5e272df/kill-screen-processes.ps1",
          "e20e76defc950c39971d3e3a796b73173a9c3bebb49dcf94172abb6eab54517a", kind="ps1"),
        T("Habibi Mod Analyzer", "Checks the mods in the folder you indicate and tells you if they are verified or "
          "not. It also checks suspicious strings.", kind="cmd",
          cmd="""powershell -command "irm 'https://raw.githubusercontent.com/HadronCollision/PowershellScripts/refs/heads/main/HabibiModAnalyzer.ps1' | iex\""""),
        T("Macro Catcher", "Detects multiple mouse macro options and opened software", kind="cmd",
          cmd="""powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/zeezyexe/macro-scanner/refs/heads/main/catchmacro.ps1')\""""),
        T("SSITA Process Info", "Check certain services and processes: status, uptime, suspended threads and "
          "other additional data.", kind="cmd",
          cmd="""powershell -command "irm https://raw.githubusercontent.com/ScreenShareITA/ScreenShare/refs/heads/main/SSITAProcessInfo.ps1 | iex\""""),
        T("PureIntent BAM", "A script almost identical to RedLotusBam, but with additional information. "
          "You will be able to view the Bam Entries.", kind="cmd",
          cmd="""powershell -command "irm 'https://raw.githubusercontent.com/PureIntent/ScreenShare/main/Bam.ps1' | iex\""""),
        T("P1AE Class Loader Dump", "Connects to the live javaw.exe and dumps all class loaders + the classes each "
          "one loaded. Discovery tool for class-level injection.", kind="cmd",
          cmd="""powershell -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/p1aegg/powershell/main/ClassLoaderDump.ps1)\""""),
        T("Yarp's Mod Analyzer", "Runs YarpLetapStan mod analyzer v6.0", kind="cmd",
          cmd="""powershell -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/YarpLetapStan/PowershellScripts/refs/heads/main/YarpsModAnalyzer6.0.ps1')\""""),
        T("Nicc Services Checker", "Run Nicc/Services-checker from GitHub", kind="cmd",
          cmd="""powershell -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/NiccBlahh/ServiceChecker/refs/heads/main/ServiceChecker.ps1')\""""),
        T("Decrypt Blocker", "Enumerates all system volumes (with letter, without letter and RAW).", kind="cmd",
          cmd="""powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; irm 'https://raw.githubusercontent.com/lea13245/decrypt-bitlocker/refs/heads/main/decrypt-bitlocker.ps1' | iex\""""),
        T("Prefetch Integrity", "Analyzes Prefetch Integrity for Bypass Attempts", kind="cmd",
          cmd="""powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; irm 'https://raw.githubusercontent.com/bacanoicua/Screenshare/main/RedLotusPrefetchIntegrityAnalyzer.ps1' | iex\""""),
        T("JVM Inspector", "Gets the actual Java/Javaw processes and inspects the CommandLine of each one.", kind="cmd",
          cmd="""powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; irm 'https://raw.githubusercontent.com/MeowTonynoh/Tonynoh-PS1/refs/heads/main/JVM-Inspector.ps1' | iex\""""),
        T("Class Loader Dump", "Detects classes that have been loaded outside the conventional folders like mods, "
          "libraries, processed mods, etc.", kind="cmd",
          cmd="""powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; irm 'https://raw.githubusercontent.com/p1aegg/powershell/refs/heads/main/ClassLoaderDump.ps1' | iex\""""),
        T("Signatures", "Verifies paths of files saved in a .txt and tells you if the file exists there and if it "
          "has a signature.", kind="cmd",
          cmd="""powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; irm 'https://github.com/Orbdiff/powershell/raw/refs/heads/main/signaturesparser.ps1' | iex\""""),
        T("BAM Parser Script", "BAM Parser but in a script made by spokwn", kind="cmd",
          cmd="""powershell -command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass; irm 'https://raw.githubusercontent.com/spokwn/powershells/refs/heads/main/bamparser.ps1' | iex\""""),
    ]),
    ("other", "Other Tools", [
        T("Jarabel", "Locate .jar files with detailed checks (download page in browser)",
          url="https://www.mediafire.com/file/3ejw2o0un4ggjr3/Jarabel.exe/file", kind="browser"),
        T("Luyten", "Luyten Java decompiler (put Luyten.exe in tools/other)", "Luyten.exe", kind="manual"),
        T("Everything", "Everything search engine", "Everything-1.4.1.1032.x86-Setup.exe",
          "https://www.voidtools.com/Everything-1.4.1.1032.x86-Setup.exe",
          "781a31b440045219752a1bb40fbd204b1d96964d4bf56af01b18e3d549b037aa", kind="installer"),
        T("System Informer", "A highly powerful, multipurpose tool that helps you monitor system resources, debug "
          "software, and detect malware. Makes accessing services and processes very easy.",
          "systeminformer-build-canary-setup.exe",
          GH + "winsiderss/si-builds/releases/download/4.0.26255.346/systeminformer-build-canary-setup.exe",
          "094eeed9bca1857902f093d62fcff7f3ed11af87791b4d363724fb4955fbbbeb", kind="installer"),
        T("MacroScanner", "Automated macro scanner for users doing SS.", "MacroScanner.exe",
          GH + "Lafferrr/MacroScanner/releases/download/MAW/MacroScanner.exe"),
        T("VirusTotal", "VirusTotal aggregates many antivirus products and online scan engines",
          url="https://www.virustotal.com/gui/home/upload", kind="browser"),
        T("Browser Checker", "Scan a users browser for malicious cheat client website visits / tells you if they "
          "downloaded a cheat client from that website", "MSC.Browser.Scanner.Setup.1.0.0.exe",
          GH + "ricniclac2/msc-browser-scanner/releases/download/Beta/MSC.Browser.Scanner.Setup.1.0.0.exe",
          kind="installer"),
        T("PJ Cheat Scanner Lite", "Strings Checker (put PJ Cheat Scanner Lite.exe in tools/other)",
          "PJ Cheat Scanner Lite.exe", kind="manual"),
        T("Java Library Analizer", "Lafferr Java Library Analyzer (put Java Library Analizer.exe in tools/other)",
          "Java Library Analizer.exe", kind="manual"),
        T("Siege", "Siege is an automatic scan tool aimed mainly at Minecraft screenshares.", "Siege.exe",
          GH + "praiselily/Siege/releases/download/Scanner/Siege.exe"),
    ]),
    ("bysystem2", "BySystem2", [
        T("Service Enabler", "Detects and manages enabled/disabled services (script from lilith-ps).", kind="cmd",
          cmd="powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Service-Enabler.ps1)"),
        T("PapeleraRecycle", "Lists the files in the Recycle Bin with their date and time.", kind="native",
          cmd='forfiles /P C:\\$Recycle.Bin /C "cmd /c echo @file @fdate @ftime"'),
        T("Services Check", "Checks the services on the PC (script from lilith-ps).", kind="cmd",
          cmd="powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass && powershell Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/praiselily/lilith-ps/refs/heads/main/Services.ps1)"),
    ]),
    ("dependencies", "Dependencies", [
        T(".NET 10.0", "The .NET Desktop Runtime enables you to run existing Windows desktop applications.",
          "windowsdesktop-runtime-10.0.5-win-x64.exe",
          "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/10.0.5/windowsdesktop-runtime-10.0.5-win-x64.exe",
          kind="installer"),
        T(".NET 9.0", "The .NET Desktop Runtime enables you to run existing Windows desktop applications.",
          "windowsdesktop-runtime-9.0.14-win-x64.exe",
          "https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/9.0.14/windowsdesktop-runtime-9.0.14-win-x64.exe",
          kind="installer"),
        T("Microsoft Visual C++ v14", "Runtime library and compiler toolset used by Microsoft to build, run, and "
          "execute C++ applications.", "vc_redist.x64.exe", "https://aka.ms/vc14/vc_redist.x64.exe",
          kind="installer"),
        T("Java", "Designed to run, develop, and manage robust, object-oriented applications on Windows.",
          "JavaSetup.exe",
          "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=253606_2fde65a2208f40a5b5f4c844b0dff092",
          kind="installer"),
    ]),
]


# ======================= EJECUCIÓN =======================
def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ssl_ctx():
    # certificados de Windows + los de certifi (arregla CERTIFICATE_VERIFY_FAILED)
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    return ctx


def download(url, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    tmp = dest + ".part"
    try:
        with urllib.request.urlopen(req, timeout=90, context=ssl_ctx()) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"No se pudo descargar (HTTP {e.code}).\n{url}")
    except Exception as e:
        raise RuntimeError(f"No se pudo descargar, revisá tu internet o el antivirus.\n{e}\n{url}")
    os.replace(tmp, dest)


def safe_extract(zp, d):
    root = os.path.realpath(d)
    with zipfile.ZipFile(zp) as z:
        for m in z.namelist():
            tgt = os.path.realpath(os.path.join(d, m))
            if tgt != root and not tgt.startswith(root + os.sep):
                raise RuntimeError("El ZIP tiene rutas inseguras, cancelado.")
        z.extractall(d)


def find_exe(folder, name):
    for r, _, files in os.walk(folder):
        for f in files:
            if f.lower() == name.lower():
                return os.path.join(r, f)
    return None


AV_MSG = ("El archivo desapareció justo después de descargarlo: casi seguro lo borró el antivirus "
          "(Windows Defender). Agregá la carpeta tools como exclusión en Seguridad de Windows y probá de nuevo.")


def log_error(name, tb):
    try:
        with open(os.path.join(base_dir(), "System2Tool.log"), "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {name}\n{tb}\n")
    except Exception:
        pass


def ensure(t, cat):
    folder = os.path.join(tools_dir(), cat)
    if t["kind"] in ("zip", "zipcli"):
        d = os.path.join(folder, norm(t["name"]))
        exe = find_exe(d, t["path"]) if os.path.isdir(d) else None
        if not exe:
            zp = os.path.join(folder, norm(t["name"]) + ".zip")
            download(t["url"], zp)
            safe_extract(zp, d)
            os.remove(zp)
            exe = find_exe(d, t["path"])
            if not exe:
                raise RuntimeError(f"No encontré {t['path']} dentro del ZIP.")
        return exe
    dest = os.path.join(folder, t["path"])
    if os.path.exists(dest) and (not t["sha"] or sha256(dest) == t["sha"]):
        return dest
    download(t["url"], dest)
    if not os.path.exists(dest):
        raise RuntimeError(AV_MSG + "\n" + dest)
    if t["sha"] and sha256(dest) != t["sha"]:
        got = sha256(dest)
        os.remove(dest)
        raise RuntimeError("El hash SHA-256 del archivo descargado no coincide, se canceló por seguridad.\n"
                           f"Esperado: {t['sha']}\nRecibido: {got}")
    return dest


def run_admin(exe, params=""):
    if os.name != "nt":
        raise RuntimeError("Esta función solo funciona en Windows.")
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    if r <= 32:
        raise RuntimeError("No se pudo abrir (¿cancelaste el permiso de administrador?).")


def run_ps1(path):
    run_admin("powershell.exe", f'-NoExit -ExecutionPolicy Bypass -File "{path}"')


def execute(t, cat):
    k, name = t["kind"], t["name"]
    if k == "browser":
        webbrowser.open(t["url"])
        return tr(f"Abriendo {name} en el navegador", f"Opening {name} in the browser")
    if k == "native":
        if " " not in t["cmd"]:
            os.startfile(t["cmd"])
        else:
            run_admin("cmd.exe", "/k " + t["cmd"])
        return tr(f"Abierto: {name}", f"Opened: {name}")
    if k == "cmd":
        run_admin("cmd.exe", "/k " + t["cmd"])
        return tr(f"Ejecutando {name}…", f"Running {name}…")
    if k == "embed":
        p = os.path.join(tempfile.gettempdir(), norm(name) + ".ps1")
        with open(p, "w", encoding="utf-8") as f:
            f.write(t["cmd"])
        run_ps1(p)
        return tr(f"Ejecutando {name}…", f"Running {name}…")
    if k == "manual":
        p = os.path.join(tools_dir(), cat, t["path"])
        if not os.path.exists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            raise RuntimeError(f"Poné {t['path']} en: {os.path.dirname(p)}")
        run_admin(p)
        return tr(f"Abierto: {name}", f"Opened: {name}")
    p = ensure(t, cat)
    if not os.path.exists(p):
        raise RuntimeError(AV_MSG + "\n" + p)
    if k == "ps1":
        run_ps1(p)
    elif k == "zipcli":
        run_admin("cmd.exe", f'/k ""{p}" -h"')
    elif k == "installer":
        os.startfile(p)
    else:
        run_admin(p)
    return tr(f"Abierto: {name}", f"Opened: {name}")


# ---------------- gatito bailando ----------------
class DancingCat(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(56, 56)
        self.movie = None
        gif = res("octocat.gif")  # si ponés este gif al lado, lo usa en vez del dibujo
        if os.path.exists(gif):
            self.movie = QMovie(gif)
            self.lbl = QLabel(self)
            self.lbl.setFixedSize(56, 56)
            self.lbl.setScaledContents(True)
            self.lbl.setMovie(self.movie)
        else:
            self.t = QTimer(self)
            self.t.timeout.connect(self.update)
            self.t.start(30)

    def start(self):
        if self.movie:
            self.movie.start()

    def stop(self):
        if self.movie:
            self.movie.stop()

    def paintEvent(self, _):
        if self.movie:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        t = time.time() * 7
        p.translate(28, 32 + math.sin(t * 2) * 2.5)
        p.rotate(math.sin(t) * 12)
        body = QColor(235, 235, 240)
        p.setPen(Qt.NoPen)
        p.setBrush(body)
        p.drawEllipse(QRectF(-12, 2, 24, 22))                      # cuerpo
        p.drawEllipse(QRectF(-14, -20, 28, 24))                    # cabeza
        for s in (-1, 1):                                          # orejas
            p.drawPolygon(QPolygonF([QPointF(s*14, -10), QPointF(s*6, -20), QPointF(s*13, -27)]))
        p.setBrush(QColor(20, 20, 25))                             # ojos
        p.drawEllipse(QRectF(-8, -11, 4, 5)); p.drawEllipse(QRectF(4, -11, 4, 5))
        p.setBrush(RED)
        p.drawEllipse(QRectF(-2, -5, 4, 3))                        # nariz
        p.setPen(QPen(body, 5, Qt.SolidLine, Qt.RoundCap))         # brazos
        p.drawLine(-11, 8, -19, 8 - int(math.sin(t * 2) * 10) - 6)
        p.drawLine(11, 8, 19, 8 + int(math.sin(t * 2) * 10) - 6)
        path = QPainterPath(QPointF(10, 20))                       # cola
        path.quadTo(24, 18 + math.sin(t * 2) * 6, 20, 4)
        p.setBrush(Qt.NoBrush)
        p.drawPath(path)


# ---------------- estela roja ----------------
class Trail(QWidget):
    LIFE = 0.55

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.pts = deque(maxlen=60)
        t = QTimer(self); t.timeout.connect(self.update); t.start(16)

    def add(self, pos):
        self.pts.append((QPointF(pos), time.time()))

    def paintEvent(self, _):
        now = time.time()
        while self.pts and now - self.pts[0][1] > self.LIFE:
            self.pts.popleft()
        if len(self.pts) < 2:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        L = list(self.pts)
        for a, b in zip(L, L[1:]):
            k = max(0.0, 1 - (now - b[1]) / self.LIFE)
            for w, al in ((14, 50), (7, 110), (3, 255)):           # glow rojo
                c = QColor(*theme()["rgb"]); c.setAlpha(int(al * k))
                p.setPen(QPen(c, w * k + 1, Qt.SolidLine, Qt.RoundCap))
                p.drawLine(a[0], b[0])




class CatButton(QPushButton):
    """Botón de ajustes: gatito que cambia de color con el tema."""
    def __init__(self):
        super().__init__()
        self.setFixedSize(42, 42)
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("Ajustes / Settings")
        self._h = False

    def enterEvent(self, e):
        self._h = True; self.update()

    def leaveEvent(self, e):
        self._h = False; self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        ac = QColor(*theme()["rgb"])
        if self._h:
            g = QColor(ac); g.setAlpha(60); p.setPen(Qt.NoPen); p.setBrush(g)
            p.drawEllipse(QRectF(1, 1, 40, 40))
        p.translate(21, 23)
        p.setPen(QPen(ac, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.setBrush(QColor(12, 12, 18, 235))
        p.drawPolygon(QPolygonF([QPointF(-13, -4), QPointF(-12, -16), QPointF(-4, -10)]))   # orejas
        p.drawPolygon(QPolygonF([QPointF(13, -4), QPointF(12, -16), QPointF(4, -10)]))
        p.drawEllipse(QRectF(-14, -11, 28, 24))                                             # cabeza
        p.setPen(Qt.NoPen); p.setBrush(ac)
        p.drawEllipse(QRectF(-8, -3, 5, 6)); p.drawEllipse(QRectF(3, -3, 5, 6))              # ojos
        p.setBrush(QColor(255, 255, 255))
        p.drawEllipse(QRectF(-6.5, -2, 1.8, 2.2)); p.drawEllipse(QRectF(4.5, -2, 1.8, 2.2))
        p.setBrush(ac)
        p.drawPolygon(QPolygonF([QPointF(-2, 4), QPointF(2, 4), QPointF(0, 6.5)]))          # nariz
        p.setPen(QPen(ac, 1.2, Qt.SolidLine, Qt.RoundCap)); p.setBrush(Qt.NoBrush)
        for s in (-1, 1):                                                                   # bigotes
            p.drawLine(QPointF(s*8, 5), QPointF(s*17, 3)); p.drawLine(QPointF(s*8, 7), QPointF(s*17, 9))


class Bus(QObject):
    done = Signal(str)


class Card(QPushButton):
    def __init__(self, name, desc):
        super().__init__()
        self.setCursor(Qt.PointingHandCursor)
        self.setMouseTracking(True)
        self.setMinimumHeight(112)
        self.raw = desc
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        t = QLabel(name); t.setObjectName("ct")
        d = QLabel(); d.setObjectName("cd"); d.setWordWrap(True)
        self.dlabel = d
        self.refresh()
        for w in (t, d):
            w.setAttribute(Qt.WA_TransparentForMouseEvents)
        lay.addWidget(t); lay.addWidget(d); lay.addStretch()

    def refresh(self):
        full = desc_tr(self.raw)
        self.setToolTip(full)
        self.dlabel.setText(full if len(full) <= 100 else full[:97].rstrip() + "…")


class Main(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System2 Tool")
        self.setWindowIcon(QIcon(res("icon.ico")))
        self.resize(1200, 740)
        self.setMouseTracking(True)
        load_settings()
        self.bg = QPixmap(res(theme()["bg"]))
        self.busy = False
        self.t0 = 0
        self.bus = Bus(); self.bus.done.connect(self.finish)

        name = QLabel("System Tool-"); name.setObjectName("brand")
        sub = QLabel("By: Pipe"); sub.setObjectName("sub")
        self.brand = name
        titles = QVBoxLayout(); titles.setSpacing(0); titles.addWidget(name); titles.addWidget(sub)
        self.gear = CatButton()
        self.gear.clicked.connect(self.show_menu)
        head = QHBoxLayout(); head.addLayout(titles); head.addStretch()
        head.addWidget(self.gear, 0, Qt.AlignTop)

        self.cards = []
        self.stack = QStackedWidget()
        tabs = QHBoxLayout(); tabs.setSpacing(0)
        group = QButtonGroup(self); group.setExclusive(True)
        for i, (cat, label, items) in enumerate(TABS):
            b = QPushButton(label); b.setObjectName("tab"); b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor); b.setMouseTracking(True)
            b.clicked.connect(lambda _, n=i: self.stack.setCurrentIndex(n))
            group.addButton(b); tabs.addWidget(b)
            if i == 0:
                b.setChecked(True)
            inner = QWidget(); grid = QGridLayout(inner)
            grid.setContentsMargins(0, 12, 6, 6); grid.setSpacing(8)
            for n, t in enumerate(items):
                c = Card(t["name"], t["desc"]); self.cards.append(c)
                c.clicked.connect(lambda _, t=t, cat=cat: self.run(t, cat))
                grid.addWidget(c, n // 4, n % 4)
            for col in range(4):
                grid.setColumnStretch(col, 1)
            grid.setRowStretch(len(items) // 4 + 1, 1)
            page = QScrollArea(); page.setWidgetResizable(True); page.setFrameShape(QFrame.NoFrame)
            page.setWidget(inner); page.viewport().setAutoFillBackground(False)
            self.stack.addWidget(page)
        tabs.addStretch()

        self.cat = DancingCat(); self.cat.hide()
        self.bar = QProgressBar(); self.bar.setRange(0, 0); self.bar.setFixedHeight(10)
        self.bar.setTextVisible(False); self.bar.hide()
        self.status = QLabel(""); self.status.setObjectName("status")
        foot = QHBoxLayout(); foot.addWidget(self.cat); foot.addWidget(self.status)
        foot.addWidget(self.bar, 1); foot.addStretch()

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 8, 14, 10)
        root.addLayout(head); root.addSpacing(6)
        root.addLayout(tabs); root.addWidget(self.stack, 1); root.addLayout(foot)

        self.apply_theme()

        self.trail = Trail(self); self.trail.setGeometry(self.rect()); self.trail.raise_()
        QApplication.instance().installEventFilter(self)

    def apply_theme(self):
        th = theme()
        self.bg = QPixmap(res(th["bg"]))
        ac, hv = th["accent"], th["hover"]
        self.setStyleSheet(f"""
            QLabel#brand{{color:{ac};font-size:17px;font-weight:800;background:transparent;}}
            QLabel#sub{{color:white;font-size:11px;background:transparent;}}
            QLabel#status{{color:white;background:transparent;font-size:12px;}}
            QPushButton#tab{{color:#ddd;background:rgba(0,0,0,70);border:none;
                border-bottom:2px solid transparent;padding:12px 11px;font-weight:600;font-size:12px;}}
            QPushButton#tab:hover{{color:{hv};}}
            QPushButton#tab:checked{{color:white;border-bottom:2px solid {ac};background:rgba(0,0,0,110);}}
            QScrollArea{{background:transparent;border:none;}}
            QScrollArea > QWidget > QWidget{{background:transparent;}}
            QScrollBar:vertical{{background:rgba(0,0,0,80);width:8px;margin:0;}}
            QScrollBar::handle:vertical{{background:{th['scroll']};border-radius:4px;min-height:30px;}}
            QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
            Card{{background:{th.get('card','rgba(10,8,10,150)')};border:1px solid {th['border']};text-align:left;}}
            Card:hover{{background:{th['cardhov']};border:1px solid {ac};}}
            QLabel#ct{{color:white;font-weight:700;font-size:13px;background:transparent;}}
            QLabel#cd{{color:#e0e0e0;font-size:12px;background:transparent;}}
            QProgressBar{{background:rgba(255,255,255,40);border:none;border-radius:5px;}}
            QProgressBar::chunk{{background:{ac};border-radius:5px;}}
            QToolTip{{color:white;background:{th['tipbg']};border:1px solid {ac};}}
            QMenu{{background:{th['tipbg']};color:white;border:1px solid {ac};padding:4px;}}
            QMenu::item{{padding:6px 22px;}}
            QMenu::item:selected{{background:{th['cardhov']};}}
            QMenu::separator{{height:1px;background:{th['border']};margin:4px 6px;}}
        """)
        self.update()

    def show_menu(self):
        m = QMenu(self)
        m.addSection(tr("Idioma", "Language"))
        for code, label in (("es", "Español"), ("en", "English")):
            a = m.addAction(("✔  " if SETTINGS["lang"] == code else "     ") + label)
            a.triggered.connect(lambda _, c=code: self.set_lang(c))
        m.addSeparator()
        m.addSection(tr("Tema", "Theme"))
        for code, label in (("red", tr("Rojo (clásico)", "Red (classic)")),
                            ("eiffel", tr("Torre Eiffel · Morado", "Eiffel Tower · Purple")),
                            ("blue", tr("Laguna nocturna · Azul", "Night lagoon · Blue")),
                            ("unlimited", tr("Ilimitado", "Unlimited"))):
            a = m.addAction(("✔  " if SETTINGS["theme"] == code else "     ") + label)
            a.triggered.connect(lambda _, c=code: self.set_theme(c))
        m.exec(self.gear.mapToGlobal(self.gear.rect().bottomLeft()))

    def set_lang(self, c):
        SETTINGS["lang"] = c; save_settings()
        for card in self.cards:
            card.refresh()

    def set_theme(self, c):
        SETTINGS["theme"] = c; save_settings(); self.apply_theme()

    def eventFilter(self, obj, ev):
        if ev.type() == QEvent.MouseMove and isinstance(obj, QWidget) and obj.window() is self:
            w = obj
            while w is not None and not isinstance(w, QPushButton):
                w = w.parentWidget()
            if w is not None:  # rastro solo sobre una tool / pestaña
                self.trail.add(self.mapFromGlobal(ev.globalPosition().toPoint()))
        return super().eventFilter(obj, ev)

    def resizeEvent(self, e):
        self.trail.setGeometry(self.rect()); self.trail.raise_()

    def paintEvent(self, _):
        p = QPainter(self)
        if not self.bg.isNull():
            s = self.bg.scaled(self.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
            p.drawPixmap((self.width() - s.width()) // 2, (self.height() - s.height()) // 2, s)
        p.fillRect(self.rect(), QColor(*theme()['overlay']))
        if theme().get("slogan"):
            p.setRenderHint(QPainter.Antialiasing)
            txt = tr("Todos los caminos llevan al Bypass", "All roads lead to the Bypass")
            f = QFont("Segoe UI", max(18, self.width() // 24)); f.setBold(True)
            p.setFont(f)
            r = QRectF(self.width() * 0.08, 0, self.width() * 0.84, self.height())
            flags = int(Qt.AlignCenter | Qt.TextWordWrap)
            p.setPen(QColor(0, 0, 0, 200))
            for dx, dy in ((3, 3), (-2, 2), (2, -2), (0, 4)):          # sombra
                p.drawText(r.translated(dx, dy), flags, txt)
            p.setPen(QColor(255, 226, 150, 235))
            p.drawText(r, flags, txt)

    def run(self, t, cat):
        if self.busy:
            return
        if t["kind"] == "cmd":
            r = QMessageBox.question(
                self, "System2 Tool",
                tr(f"«{t['name']}» descarga y ejecuta un script desde internet (GitHub) como administrador.\n\n¿Continuar?",
                   f"«{t['name']}» downloads and runs a script from the internet (GitHub) as administrator.\n\nContinue?"))
            if r != QMessageBox.Yes:
                return
        self.busy = True
        self.t0 = time.time()
        self.status.setText(tr(f"Cargando {t['name']}…", f"Loading {t['name']}…"))
        self.cat.show(); self.cat.start(); self.bar.show()
        threading.Thread(target=self.work, args=(t, cat), daemon=True).start()

    def work(self, t, cat):
        try:
            msg = execute(t, cat)
        except Exception as e:
            log_error(t["name"], traceback.format_exc())
            msg = f"Error: {e}"
        self.bus.done.emit(msg)

    def finish(self, msg):
        wait = max(0, int(1300 - (time.time() - self.t0) * 1000))
        QTimer.singleShot(wait, lambda: self._end(msg))

    def _end(self, msg):
        self.cat.stop(); self.cat.hide(); self.bar.hide()
        self.busy = False
        if msg.startswith("Error"):
            self.status.setText(tr("Error (ver ventana)", "Error (see window)"))
            QMessageBox.warning(self, "System2 Tool", msg + tr("\n\nSe guardó en System2Tool.log", "\n\nSaved to System2Tool.log"))
        else:
            self.status.setText(msg)
        QTimer.singleShot(8000, lambda: self.status.setText(""))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = Main(); w.show()
    sys.exit(app.exec())
