# SchulePI – Raspberry Pi Kiosk für Schulportal Hessen

**SchulePI** ist ein Komplettskript, das einen Raspberry Pi in einen **zuverlässigen Kiosk-Modus** für das Schulportal Hessen verwandelt.  
Es richtet den Pi als **vertretungsplanfähigen Monitor** ein – mit automatischem Start, Auto-Updates, SSH-Fernwartung und schreibgeschütztem Modus.

---

## Features

- **Einfache Bedienung über UI**  
  Starten mit:
  ```bash
  sudo python3 schulePI.py
  ```
  → Die grafische Oberfläche (Tkinter) öffnet sich automatisch.

- **Kiosk-Modus mit Chromium**  
  - Autostart des Browsers im Vollbild (Kiosk)  
  - Crash-Respawn, Autologin  
  - Monitor AN/AUS per Cron

- **Verwaltung**  
  - Auto-Updates (`unattended-upgrades`)  
  - Manuelle Updates (auch `dist-upgrade`)  
  - Self-Update-Funktion für das Skript selbst  
  - Anzeige-Einstellungen: Screensaver aus, Mauszeiger aus

- **SSH-Fernwartung**  
  - Aktivieren/Deaktivieren, Port ändern  
  - Passwort-Login optional (Standard: nur Schlüssel)  
  - Öffentlichen SSH-Key hinterlegen  
  - Firewall (UFW) aktivieren und Port freigeben  
  - Hostkeys neu erzeugen  
  - **Nach Einrichtung werden Host/IP, Port, Login und Key angezeigt**

- **Schreibschutz (OverlayFS)**  
  - Aktivierbar mit einem Klick in der UI  
  - Schutz bleibt auch nach Stromausfall aktiv  
  - **Deaktivieren nur mit Passwort `0825`**  
  - Button **„Fertig & sperren (RO + Neustart)“** für den finalen Rollout

---

## Systemvoraussetzungen

- **Hardware:** Raspberry Pi 3 / 3B+ / 4 / 400 (empfohlen: Pi 4), Micro‑SD ≥ **16 GB** (Class 10), Netzteil
  - Pi 3: 5 V / **2.5 A** · Pi 4/400: 5 V / **3 A**
- **Anzeige:** Monitor/TV mit **HDMI**, passendes Kabel
- **Eingabegeräte (für Ersteinrichtung):** USB‑Tastatur + Maus
- **Netzwerk:** WLAN oder Ethernet mit Internetzugang
- **Betriebssystem:** Raspberry Pi OS **Bookworm** (32‑ oder 64‑bit)
  - Kiosk stabil unter **X11**. Falls Wayland aktiv ist: `raspi-config` → *Advanced Options* → **Wayland → X11**.
- **Software/Pakete:** `python3`, `python3-tk`, `chromium-browser` (siehe Installation)
- **Optional:** UFW‑Firewall, RTC‑Modul (für exakte Uhrzeit ohne Netz), Gehäuse mit aktivem Kühler


---

## Installation

1. Raspberry Pi OS (Bookworm) installieren  
2. Paketabhängigkeiten:
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-tk chromium-browser unclutter xscreensaver ufw
   ```
3. Skript herunterladen:
   ```bash
   wget https://github.com/<dein-user>/<dein-repo>/raw/main/schulePI.py
   chmod +x schulePI.py
   ```
4. Starten:
   ```bash
   sudo python3 schulePI.py
   ```

---

## Nutzung

- **UI (Standard)**  
  Startet automatisch, wenn keine Flags angegeben werden:
  ```bash
  sudo python3 schulePI.py
  ```

- **CLI (Headless/Automation)**  
  Beispiel: SSH aktivieren, Port setzen, Key hinzufügen:
  ```bash
  sudo python3 schulePI.py --no-ui --apply-config \
      --enable-ssh --ssh-port 2222 --ssh-pubkey-file ~/.ssh/id_ed25519.pub
  ```

- **Schreibschutz aktivieren**:
  ```bash
  sudo python3 schulePI.py --enable-ro
  sudo reboot
  ```

- **Schreibschutz deaktivieren (PW 0825)**:
  ```bash
  sudo python3 schulePI.py --disable-ro --pw 0825
  ```

---

## Hinweise

- UI benötigt `python3-tk`.  
- SSH-Zugangsdaten (IP, Port, User, Key) werden nach Einrichtung angezeigt.  
- Schreibschutz erst aktivieren, wenn das System komplett eingerichtet ist.  
- Bei aktiviertem Schreibschutz sind Änderungen nach Neustart nicht persistent.

---

## Lizenz

MIT License – frei nutzbar und anpassbar.
