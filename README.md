# SchulePI – Raspberry Pi Kiosk für Schulportal Hessen

**SchulePI** ist ein Komplettskript, das einen Raspberry Pi in einen **zuverlässigen Kiosk-Modus** für das Schulportal Hessen verwandelt.  
Es richtet den Pi als **vertretungsplanfähigen Monitor** ein – mit automatischem Start, Auto-Updates, SSH-Fernwartung und schreibgeschütztem Modus.

---

## Features

- **Einfache Bedienung über UI**  
  - Start:
    ```bash
    sudo python3 schulePI.py
    ```
  - Alle Einstellungen in einer grafischen Oberfläche (Tkinter)

- **Kiosk-Modus mit Chromium**
  - Autostart im Vollbild (Kiosk)
  - Crash-Respawn, Autologin
  - Monitor AN/AUS zeitgesteuert (Cronjobs)

- **Verwaltung**
  - Auto-Updates (`unattended-upgrades`)
  - Manuelle Updates (auch `dist-upgrade`)
  - Self-Update für das Skript
  - Screensaver deaktivieren & Mauszeiger ausblenden

- **SSH-Fernwartung**
  - Aktivieren/Deaktivieren, Port einstellen
  - Passwort-Login optional (Standard: nur Schlüssel)
  - Öffentlichen SSH-Key hinterlegen
  - Firewall (UFW) aktivieren und Port freigeben
  - Hostkeys neu erzeugen
  - **Nach Einrichtung werden Host/IP, Port, Login und Key angezeigt (zum Notieren)**

- **Schreibschutz (OverlayFS)**
  - Aktivierbar per UI oder CLI
  - Überlebt Stromausfälle ohne Datenverlust
  - **Deaktivieren nur mit Passwort `0825`**
  - Button **„Fertig & sperren (RO + Neustart)“** für finalen Rollout

---

## Systemvoraussetzungen

- **Hardware:** Raspberry Pi 3 / 3B+ / 4 / 400 (empfohlen: Pi 4)  
  - Micro-SD ≥ **16 GB**, Netzteil (Pi 3: 5 V/2.5 A · Pi 4: 5 V/3 A)
- **Anzeige:** Monitor oder TV mit **HDMI**
- **Eingabegeräte (nur fürs Setup):** USB-Tastatur & Maus
- **Netzwerk:** WLAN oder Ethernet
- **Betriebssystem:** Raspberry Pi OS **Bookworm** (32-/64-bit)  
  - Kiosk stabil unter **X11**. Falls Wayland aktiv ist:  
    `raspi-config` → *Advanced Options* → **Wayland → X11**
- **Software/Pakete:** `python3`, `python3-tk`, `chromium-browser`  
- **Optional:** UFW-Firewall, RTC-Modul, Gehäuse mit Lüfter

---

## Installation

1. Raspberry Pi OS (Bookworm) installieren
2. Abhängigkeiten installieren:
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-tk chromium-browser unclutter xscreensaver ufw
