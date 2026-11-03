@echo off
title Compilando System2 Tool
cd /d "%~dp0"

echo Preparando Python 3.12 (si pregunta Y/n, escribe Y y Enter)...
py install 3.12

py -3.12 -m pip install pyside6 pyinstaller certifi
if errorlevel 1 (
  echo No se pudo instalar con 3.12, probando con el Python por defecto...
  python -m pip install pyside6 pyinstaller certifi
  set PY=python
) else (
  set PY=py -3.12
)

%PY% -m PyInstaller --noconsole --onefile --collect-data certifi --name System2Tool --icon icon.ico --add-data "fondo.jpg;." --add-data "eiffel.jpg;." --add-data "azul.jpg;." --add-data "icon.ico;." system2tool.py

if exist dist\System2Tool.exe (
  copy /y dist\System2Tool.exe System2Tool.exe >nul
  echo.
  echo Listo: System2Tool.exe creado en esta carpeta.
) else (
  echo Hubo un error al compilar.
)
pause
