#!/usr/bin/env python3
# SchulePI – Kiosk & Portal Setup (Bookworm/X11) – komplette Version
# Features:
# - Persistente Config /etc/schulepi.conf + UI (startet standardmäßig)
# - Chromium-Kiosk (Autostart, Crash-Respawn)
# - DPMS/Blanking aus, Openbox-Hotkeys
# - Monitor AN/AUS per Cron
# - Auto-Updates, manuelles Update, optional Self-Update
# - Schreibschutz (Overlay); Deaktivierung nur mit PW 0825
# - SSH-Fernwartung (enable/disable, Port, PasswordAuth, PubKey, Hostkeys-Rekey, UFW)
# - SSH-Info (IP/Port/User/+Key) nach Einrichtung (CLI-Ausgabe + UI-Popup)
# - „Fertig & sperren (RO + Neustart)“-Button
#
# Nutzung:
#   sudo python3 schulePI.py              -> UI startet
#   sudo python3 schulePI.py --no-ui ...  -> reiner CLI-Modus (Headless)

import argparse, os, shutil, subprocess, configparser
from pathlib import Path
from dataclasses import dataclass

CONFIG_PATH = Path("/etc/schulepi.conf")
RO_DISABLE_PASSWORD = "0825"

# ------------------ Helpers ------------------

def sh(cmd, check=True, capture=False, user=None):
    env = os.environ.copy()
    env.setdefault("DEBIAN_FRONTEND","noninteractive")
    if user and user != "root":
        cmd = f"sudo -u {user} " + cmd
    return subprocess.run(
        cmd, shell=True, check=check, text=True,
        stdout=(subprocess.PIPE if capture else None),
        stderr=(subprocess.PIPE if capture else None),
        env=env
    )

def command_exists(c): return shutil.which(c) is not None
def ensure_dir(p:Path): p.mkdir(parents=True, exist_ok=True)
def backup_file(p:Path):
    if p.exists() and p.is_file():
        bak = p.with_suffix(p.suffix+".bak")
        if not bak.exists(): shutil.copy2(p,bak)
def read_text(p:Path): return p.read_text("utf-8") if p.exists() else ""
def write_text(p:Path, txt:str):
    ensure_dir(p.parent); backup_file(p); p.write_text(txt,"utf-8")

def ensure_lines_in_file(p:Path, lines:list):
    cur = read_text(p).splitlines(); chg=False
    for l in lines:
        if l not in cur:
            cur.append(l); chg=True
    if chg: write_text(p, "\n".join(cur)+"\n")

def ensure_block_in_xml(p:Path, marker:str, block:str):
    tpl='<?xml version="1.0"?><lxde_config><keyboard></keyboard></lxde_config>'
    content=read_text(p) or tpl
    if marker in content: return
    if "<keyboard>" not in content:
        content += "\n<keyboard>\n</keyboard>\n"
    content = content.replace("<keyboard>", "<keyboard>\n"+block.strip()+"\n")
    write_text(p, content)

def get_desktop_user() -> str:
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "pi"

def get_user_home(user:str) -> Path:
    return Path("/root" if user=="root" else f"/home/{user}")

def get_lxsession_autostart_path(user:str) -> Path:
    return get_user_home(user)/".config/lxsession/LXDE-pi/autostart"

def get_openbox_rc_path(user:str) -> Path:
    return get_user_home(user)/".config/openbox/lxde-pi-rc.xml"

def get_chromium_binary() -> str:
    if command_exists("chromium-browser"): return "chromium-browser"
    if command_exists("chromium"): return "chromium"
    raise RuntimeError("Chromium fehlt: sudo apt install -y chromium-browser")

def cron_list():
    r=sh("crontab -l 2>/dev/null || true", check=False, capture=True)
    return r.stdout if r and r.stdout is not None else ""

def cron_install(lines:list):
    cur=cron_list().splitlines(); chg=False
    for l in lines:
        if l.strip() and l not in cur:
            cur.append(l); chg=True
    if chg:
        text="\n".join([l for l in cur if l.strip()])+"\n"
        p=subprocess.Popen(["crontab","-"], stdin=subprocess.PIPE, text=True)
        p.communicate(input=text)

def require_root():
    if os.geteuid()!=0: raise SystemExit("Root nötig (sudo)")

def time_ok(hhmm):
    try: h,m=map(int,hhmm.split(":")); return 0<=h<24 and 0<=m<60
    except: return False

def remind_x11():
    if os.environ.get("XDG_SESSION_TYPE","").lower()=="wayland":
        print("Hinweis: Wayland erkannt. In raspi-config ▸ Advanced ▸ Wayland ▸ X11 wechseln.")

# ------------------ Overlay (RO) ------------------

def find_cmdline_path() -> Path:
    for p in (Path("/boot/firmware/cmdline.txt"), Path("/boot/cmdline.txt")):
        if p.exists(): return p
    return Path("/boot/firmware/cmdline.txt")

def is_overlay_enabled() -> bool:
    return "boot=overlay" in read_text(find_cmdline_path())

def enable_overlay() -> bool:
    p=find_cmdline_path(); txt=read_text(p).strip()
    if not txt: raise RuntimeError(f"cmdline.txt leer/nicht gefunden: {p}")
    if "boot=overlay" in txt: return False
    line = " ".join((txt.splitlines()[0] if "\n" in txt else txt).split())
    write_text(p, (line+" boot=overlay").strip()+"\n"); return True

def disable_overlay() -> bool:
    p=find_cmdline_path(); txt=read_text(p)
    if not txt: raise RuntimeError(f"cmdline.txt leer/nicht gefunden: {p}")
    if "boot=overlay" not in txt: return False
    parts=[tok for tok in txt.replace("\n"," ").split(" ") if tok.strip() and tok!="boot=overlay"]
    write_text(p, " ".join(parts)+"\n"); return True

# ------------------ Updates ------------------

def enable_auto_updates(auto_reboot_time:str|None):
    sh("apt-get update -y"); sh("apt-get install -y unattended-upgrades apt-listchanges")
    write_text(Path("/etc/apt/apt.conf.d/20auto-upgrades"), "\n".join([
        'APT::Periodic::Update-Package-Lists "1";',
        'APT::Periodic::Download-Upgradeable-Packages "1";',
        'APT::Periodic::Unattended-Upgrade "1";',
        'APT::Periodic::AutocleanInterval "7";',
    ])+"\n")
    lines=[
        'Unattended-Upgrade::Remove-Unused-Dependencies "true";',
        'Unattended-Upgrade::Remove-New-Unused-Dependencies "true";',
        'Unattended-Upgrade::Automatic-Reboot "false";',
    ]
    if auto_reboot_time:
        lines[-1]='Unattended-Upgrade::Automatic-Reboot "true";'
        lines.append(f'Unattended-Upgrade::Automatic-Reboot-Time "{auto_reboot_time}";')
    write_text(Path("/etc/apt/apt.conf.d/51-schulepi-unattended"), "\n".join(lines)+"\n")
    for unit in ("apt-daily.timer","apt-daily-upgrade.timer","unattended-upgrades.service"):
        sh(f"systemctl enable --now {unit}", check=False)

def update_now(dist_upgrade:bool, autoremove_clean:bool=True):
    sh("apt-get update -y")
    if dist_upgrade:
        sh('apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dist-upgrade')
    else:
        sh('apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade')
    if autoremove_clean:
        sh("apt-get -y autoremove"); sh("apt-get -y autoclean")

def setup_self_update(url:str):
    script_dir=Path("/usr/local/sbin"); ensure_dir(script_dir)
    updater=script_dir/"schulepi-selfupdate.sh"; target=script_dir/"schulePI.py"
    sh_txt=f"""#!/bin/sh
set -eu
TMP="$(mktemp)"; curl -fsSL "{url}" -o "$TMP"
[ -s "$TMP" ] || {{ echo leer; rm -f "$TMP"; exit 1; }}
if [ ! -f "{target}" ]; then install -m 0755 "$TMP" "{target}"; rm -f "$TMP"; exit 0; fi
OLD="$(sha256sum "{target}"|awk '{{print $1}}')"; NEW="$(sha256sum "$TMP"|awk '{{print $1}}')"
[ "$OLD" != "$NEW" ] && install -m 0755 "$TMP" "{target}"
rm -f "$TMP"
"""
    write_text(updater, sh_txt); sh(f"chmod +x {updater}")
    svc=Path("/etc/systemd/system/schulepi-selfupdate.service")
    tmr=Path("/etc/systemd/system/schulepi-selfupdate.timer")
    write_text(svc, f"[Unit]\nDescription=SchulePI Self-Update\n[Service]\nType=oneshot\nExecStart={updater}\n")
    write_text(tmr, "[Unit]\nDescription=Tägliches SchulePI Self-Update\n[Timer]\nOnCalendar=*-*-* 03:10:00\nPersistent=true\n[Install]\nWantedBy=timers.target\n")
    sh("systemctl daemon-reload"); sh("systemctl enable --now schulepi-selfupdate.timer")

# ------------------ SSH / Remote Maintenance ------------------

@dataclass
class SSHOptions:
    enable: bool = False
    port: int = 22
    allow_password: bool = False   # Standard: nur Schlüssel
    pubkey_text: str | None = None
    ufw_enable: bool = False
    rekey: bool = False

def ensure_openssh_installed():
    sh("apt-get update -y"); sh("apt-get install -y openssh-server")

def ssh_write_user_key(user: str, pubkey: str):
    home = get_user_home(user)
    ssh_dir = home / ".ssh"
    auth = ssh_dir / "authorized_keys"
    ensure_dir(ssh_dir)
    cur = read_text(auth)
    if pubkey.strip() not in cur:
        write_text(auth, (cur + ("\n" if cur and not cur.endswith("\n") else "") + pubkey.strip() + "\n"))
    sh(f"chown -R {user}:{user} {ssh_dir}", check=False)
    os.chmod(ssh_dir, 0o700)
    os.chmod(auth, 0o600)

def ssh_write_da_conf(port: int, allow_password: bool):
    dconf = Path("/etc/ssh/sshd_config.d/schulepi.conf")
    lines = [
        f"Port {port}",
        "Protocol 2",
        "PermitRootLogin no",
        f"PasswordAuthentication {'yes' if allow_password else 'no'}",
        "ChallengeResponseAuthentication no",
        "UsePAM yes",
        "X11Forwarding no",
        "ClientAliveInterval 120",
        "ClientAliveCountMax 2",
        "AllowTcpForwarding no",
    ]
    write_text(dconf, "\n".join(lines) + "\n")

def ssh_enable_service(enable: bool):
    if enable:
        sh("systemctl enable --now ssh", check=False)
    else:
        sh("systemctl disable --now ssh", check=False)

def ssh_rekey_hostkeys():
    sh("systemctl stop ssh", check=False)
    sh("rm -f /etc/ssh/ssh_host_*", check=False)
    sh("ssh-keygen -A")
    sh("systemctl start ssh", check=False)

def ufw_apply(enable_flag: bool, port: int):
    if not enable_flag: 
        return
    sh("apt-get install -y ufw", check=False)
    sh("ufw --force enable", check=False)
    sh(f"ufw allow {port}/tcp", check=False)

def _get_first_ip() -> str:
    r = sh("hostname -I | awk '{print $1}'", capture=True, check=False)
    ip = (r.stdout or "").strip() if r else ""
    return ip or "<unbekannt>"

def apply_ssh_settings(sshopt: SSHOptions, desktop_user: str):
    """
    Wendet SSH-Settings an und gibt am Ende eine Notiz mit IP/Port/User (+Key) aus,
    damit man sie notieren kann. (CLI) – die UI zeigt zusätzlich ein Popup.
    """
    ensure_openssh_installed()
    ssh_write_da_conf(sshopt.port, sshopt.allow_password)
    if sshopt.pubkey_text:
        ssh_write_user_key(desktop_user, sshopt.pubkey_text)
    ssh_enable_service(sshopt.enable)
    ufw_apply(sshopt.ufw_enable, sshopt.port)
    if sshopt.rekey:
        ssh_rekey_hostkeys()
    if sshopt.enable:
        sh("systemctl restart ssh", check=False)
        # --- Notiz ausgeben ---
        ip = _get_first_ip()
        print("\nSSH-Zugang eingerichtet (notieren):")
        print(f"  Host/IP : {ip}")
        print(f"  Port    : {sshopt.port}")
        print(f"  Benutzer: {desktop_user}")
        if sshopt.pubkey_text:
            print("  Public Key:")
            print("   ", sshopt.pubkey_text.strip())

# ------------------ Setup steps ------------------

def set_timezone():
    try: sh("timedatectl set-timezone Europe/Berlin")
    except subprocess.CalledProcessError: print("Warnung: Zeitzone konnte nicht gesetzt werden.")

def ensure_autologin_desktop():
    sh("raspi-config nonint do_boot_behaviour B4", check=False)

def install_utilities(hide_cursor:bool, xscreensaver:bool):
    pkgs=[]
    if xscreensaver: pkgs.append("xscreensaver")
    if hide_cursor:  pkgs.append("unclutter")
    if pkgs:
        sh("apt-get update -y"); sh("apt-get install -y "+" ".join(pkgs))

def install_kiosk_wrapper(user:str, url:str, chromium:str):
    bin_dir = get_user_home(user)/".local/bin"
    ensure_dir(bin_dir)
    wrapper = bin_dir/"chromium-kiosk.sh"
    script = f"""#!/bin/bash
set -e
URL="{url}"
CMD="{chromium} --no-default-browser-check --no-first-run --disable-infobars --disable-session-crashed-bubble --overscroll-history-navigation=0 --kiosk --app=$URL"
until $CMD; do sleep 2; done
"""
    write_text(wrapper, script)
    sh(f"chown -R {user}:{user} {bin_dir}", check=False)
    sh(f"chmod +x {wrapper}", check=False)
    return wrapper

def write_autostart_kiosk(user:str, school_number:str, url_template:str):
    autopath = get_lxsession_autostart_path(user)
    ensure_dir(autopath.parent)
    chromium = get_chromium_binary()
    url = url_template.format(school_number=school_number)
    wrapper = install_kiosk_wrapper(user, url, chromium)
    lines = ["@xset s off", "@xset -dpms", "@xset s noblank", f"@{wrapper}"]
    ensure_lines_in_file(autopath, lines)
    sh(f"chown -R {user}:{user} {autopath.parent}", check=False)

def setup_monitor_schedule(on_time:str, off_time:str, weekdays:str):
    on  = f"{int(on_time.split(':')[1])} {int(on_time.split(':')[0])} * * {weekdays} DISPLAY=:0 xset dpms force on"
    off = f"{int(off_time.split(':')[1])} {int(off_time.split(':')[0])} * * {weekdays} DISPLAY=:0 xset dpms force off"
    cron_install([off,on])

def setup_hdmi_hotkeys(user:str):
    rc=get_openbox_rc_path(user)
    block="""<!-- HDMI -->
<keybind key="W-F9"><action name="Execute"><command>vcgencmd display_power 1</command></action></keybind>
<keybind key="W-F10"><action name="Execute"><command>vcgencmd display_power 0</command></action></keybind>"""
    ensure_dir(rc.parent); ensure_block_in_xml(rc, "vcgencmd display_power 1", block)
    sh(f"chown -R {user}:{user} {rc.parent}", check=False)

# ------------------ Config I/O ------------------

@dataclass
class SSHOptionsConfig:
    enable: bool = False
    port: int = 22
    allow_password: bool = False
    pubkey_text: str | None = None
    ufw_enable: bool = False

@dataclass
class SetupOptions:
    school:str
    url_template:str="https://start.schulportal.hessen.de/vertretungsplan.php?a=view&i={school_number}"
    on_time:str="07:00"; off_time:str="17:15"; weekdays:str="1-5"
    use_xscreensaver:bool=True; use_unclutter:bool=True
    enable_auto_updates:bool=False; auto_reboot_time:str|None=None
    update_now:bool=False; dist_upgrade:bool=False
    self_update_url:str|None=None
    desktop_user:str="pi"
    read_only_mode:bool=False
    ssh: SSHOptions = SSHOptions()

def load_config(default_user:str) -> SetupOptions:
    cfg=configparser.ConfigParser()
    if CONFIG_PATH.exists(): cfg.read(CONFIG_PATH)
    sec=cfg["portal"] if "portal" in cfg else {}
    upd=cfg["updates"] if "updates" in cfg else {}
    pro=cfg["protect"] if "protect" in cfg else {}
    sshc=cfg["ssh"] if "ssh" in cfg else {}
    ro_real=is_overlay_enabled()
    def getbool(d, k, default=False):
        v = d.get(k, str(default)).strip().lower()
        return v in ("1","true","yes","on")
    return SetupOptions(
        school=sec.get("school",""),
        url_template=sec.get("url_template","https://start.schulportal.hessen.de/vertretungsplan.php?a=view&i={school_number}"),
        on_time=sec.get("on_time","07:00"),
        off_time=sec.get("off_time","17:15"),
        weekdays=sec.get("weekdays","1-5"),
        use_xscreensaver=getbool(sec,"use_xscreensaver",True),
        use_unclutter=getbool(sec,"use_unclutter",True),
        enable_auto_updates=getbool(upd,"enable_auto_updates",False),
        auto_reboot_time=(upd.get("auto_reboot_time") or None),
        update_now=False, dist_upgrade=False,
        self_update_url=(upd.get("self_update_url") or None),
        desktop_user=sec.get("desktop_user", default_user),
        read_only_mode=(ro_real or getbool(pro,"read_only_mode",False)),
        ssh=SSHOptions(
            enable=getbool(sshc,"enable",False),
            port=int(sshc.get("port","22")),
            allow_password=getbool(sshc,"allow_password",False),
            pubkey_text=(sshc.get("pubkey_text") or None),
            ufw_enable=getbool(sshc,"ufw_enable",False),
            rekey=False
        )
    )

def save_config(opt:SetupOptions):
    cfg=configparser.ConfigParser()
    cfg["portal"]={
        "school":opt.school, "url_template":opt.url_template,
        "on_time":opt.on_time, "off_time":opt.off_time, "weekdays":opt.weekdays,
        "use_xscreensaver":str(opt.use_xscreensaver).lower(),
        "use_unclutter":str(opt.use_unclutter).lower(),
        "desktop_user":opt.desktop_user
    }
    cfg["updates"]={
        "enable_auto_updates":str(opt.enable_auto_updates).lower(),
        "auto_reboot_time":opt.auto_reboot_time or "",
        "self_update_url":opt.self_update_url or ""
    }
    cfg["protect"]={ "read_only_mode":str(opt.read_only_mode).lower() }
    cfg["ssh"]={
        "enable":str(opt.ssh.enable).lower(),
        "port":str(opt.ssh.port),
        "allow_password":str(opt.ssh.allow_password).lower(),
        "pubkey_text":opt.ssh.pubkey_text or "",
        "ufw_enable":str(opt.ssh.ufw_enable).lower()
    }
    ensure_dir(CONFIG_PATH.parent)
    with open(CONFIG_PATH,"w",encoding="utf-8") as f: cfg.write(f)

# ------------------ Orchestration ------------------

def run_setup(opt:SetupOptions):
    remind_x11()
    set_timezone()
    ensure_autologin_desktop()
    install_utilities(hide_cursor=opt.use_unclutter, xscreensaver=opt.use_xscreensaver)
    write_autostart_kiosk(opt.desktop_user, opt.school, opt.url_template)
    setup_monitor_schedule(opt.on_time, opt.off_time, opt.weekdays)
    setup_hdmi_hotkeys(opt.desktop_user)
    if opt.enable_auto_updates: enable_auto_updates(opt.auto_reboot_time)
    if opt.update_now: update_now(opt.dist_upgrade)
    if opt.self_update_url: setup_self_update(opt.self_update_url)
    # SSH anwenden (inkl. CLI-Notiz)
    apply_ssh_settings(opt.ssh, opt.desktop_user)
    # Overlay anwenden (nur aktivieren hier; deaktivieren via Passwort-Flow/CLI)
    if opt.read_only_mode and not is_overlay_enabled():
        if enable_overlay(): print("Schreibschutz aktiviert. Neustart erforderlich.")
    print("Setup abgeschlossen. Neustart empfohlen.")

# ------------------ UI ------------------

def launch_ui():
    require_root()
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog

    default_user=get_desktop_user()
    state=load_config(default_user)
    overlay_now=is_overlay_enabled()

    root=tk.Tk(); root.title("SchulePI – Setup"); root.geometry("900x870")
    padd={'padx':8,'pady':5}

    # Portal/Kiosk
    v_school=tk.StringVar(value=state.school)
    v_url=tk.StringVar(value=state.url_template)
    v_user=tk.StringVar(value=state.desktop_user or default_user)
    v_on=tk.StringVar(value=state.on_time); v_off=tk.StringVar(value=state.off_time)
    v_wd=tk.StringVar(value=state.weekdays)
    v_xss=tk.BooleanVar(value=state.use_xscreensaver)
    v_uncl=tk.BooleanVar(value=state.use_unclutter)
    v_auto=tk.BooleanVar(value=state.enable_auto_updates)
    v_reboot=tk.StringVar(value=state.auto_reboot_time or "")
    v_selfurl=tk.StringVar(value=state.self_update_url or "")
    v_upnow=tk.BooleanVar(value=False); v_dist=tk.BooleanVar(value=False)
    v_ro=tk.BooleanVar(value=(overlay_now or state.read_only_mode))
    # SSH
    v_ssh_enable=tk.BooleanVar(value=state.ssh.enable)
    v_ssh_port=tk.StringVar(value=str(state.ssh.port))
    v_ssh_pw=tk.BooleanVar(value=state.ssh.allow_password)
    v_ssh_key=tk.StringVar(value=state.ssh.pubkey_text or "")
    v_ssh_ufw=tk.BooleanVar(value=state.ssh.ufw_enable)
    v_status=tk.StringVar(value=("GESCHÜTZT (RO)." if overlay_now else "Hinweis: Nach Einrichtung 'Fertig & sperren'."))

    frm=ttk.Frame(root); frm.pack(fill="both",expand=True,padx=10,pady=10)
    r=0
    ttk.Label(frm,text="Schulnummer").grid(row=r,column=0,sticky="w",**padd)
    e_school=ttk.Entry(frm,textvariable=v_school); e_school.grid(row=r,column=1,sticky="ew",**padd)
    r+=1
    ttk.Label(frm,text="Portal-URL ({school_number})").grid(row=r,column=0,sticky="w",**padd)
    e_url=ttk.Entry(frm,textvariable=v_url); e_url.grid(row=r,column=1,sticky="ew",**padd)
    r+=1
    ttk.Label(frm,text="Desktop-User").grid(row=r,column=0,sticky="w",**padd)
    e_user=ttk.Entry(frm,textvariable=v_user); e_user.grid(row=r,column=1,sticky="w",**padd)
    r+=1
    ttk.Label(frm,text="Monitor AN (HH:MM)").grid(row=r,column=0,sticky="w",**padd)
    e_on=ttk.Entry(frm,width=10,textvariable=v_on); e_on.grid(row=r,column=1,sticky="w",**padd)
    r+=1
    ttk.Label(frm,text="Monitor AUS (HH:MM)").grid(row=r,column=0,sticky="w",**padd)
    e_off=ttk.Entry(frm,width=10,textvariable=v_off); e_off.grid(row=r,column=1,sticky="w",**padd)
    r+=1
    ttk.Label(frm,text="Wochentage (Cron z.B. 1-5)").grid(row=r,column=0,sticky="w",**padd)
    e_wd=ttk.Entry(frm,width=10,textvariable=v_wd); e_wd.grid(row=r,column=1,sticky="w",**padd)
    r+=1
    c_xss=ttk.Checkbutton(frm,text="Screensaver deaktivieren (xscreensaver)",variable=v_xss)
    c_xss.grid(row=r,column=0,columnspan=2,sticky="w",**padd)
    r+=1
    c_uncl=ttk.Checkbutton(frm,text="Mauszeiger ausblenden (unclutter)",variable=v_uncl)
    c_uncl.grid(row=r,column=0,columnspan=2,sticky="w",**padd)

    r+=1; ttk.Separator(frm).grid(row=r,column=0,columnspan=2,sticky="ew",pady=8)

    r+=1
    c_auto=ttk.Checkbutton(frm,text="Auto-Updates (unattended-upgrades)",variable=v_auto)
    c_auto.grid(row=r,column=0,columnspan=2,sticky="w",**padd)
    r+=1
    ttk.Label(frm,text="Auto-Reboot (optional HH:MM)").grid(row=r,column=0,sticky="w",**padd)
    e_reboot=ttk.Entry(frm,width=10,textvariable=v_reboot); e_reboot.grid(row=r,column=1,sticky="w",**padd)
    r+=1
    ttk.Label(frm,text="Self-Update-URL (optional)").grid(row=r,column=0,sticky="w",**padd)
    e_selfurl=ttk.Entry(frm,textvariable=v_selfurl); e_selfurl.grid(row=r,column=1,sticky="ew",**padd)
    r+=1
    c_upnow=ttk.Checkbutton(frm,text="Jetzt Update ausführen",variable=v_upnow)
    c_upnow.grid(row=r,column=0,columnspan=2,sticky="w",**padd)
    r+=1
    c_dist=ttk.Checkbutton(frm,text="dist-upgrade verwenden",variable=v_dist)
    c_dist.grid(row=r,column=0,columnspan=2,sticky="w",**padd)

    r+=1; ttk.Separator(frm).grid(row=r,column=0,columnspan=2,sticky="ew",pady=10)

    # SSH Section
    r+=1
    ttk.Label(frm,text="Fernwartung (SSH)").grid(row=r,column=0,sticky="w",**padd)
    c_ssh=ttk.Checkbutton(frm,text="SSH aktivieren",variable=v_ssh_enable)
    c_ssh.grid(row=r,column=1,sticky="w",**padd)
    r+=1
    ttk.Label(frm,text="SSH-Port").grid(row=r,column=0,sticky="w",**padd)
    e_ssh_port=ttk.Entry(frm,width=8,textvariable=v_ssh_port); e_ssh_port.grid(row=r,column=1,sticky="w",**padd)
    r+=1
    c_ssh_pw=ttk.Checkbutton(frm,text="Passwort-Login erlauben (nicht empfohlen)",variable=v_ssh_pw)
    c_ssh_pw.grid(row=r,column=0,columnspan=2,sticky="w",**padd)
    r+=1
    ttk.Label(frm,text="Öffentlicher SSH-Schlüssel").grid(row=r,column=0,sticky="nw",**padd)
    txt_ssh_key=tk.Text(frm,height=5); txt_ssh_key.insert("1.0", v_ssh_key.get()); txt_ssh_key.grid(row=r,column=1,sticky="ew",**padd)
    r+=1
    c_ssh_ufw=ttk.Checkbutton(frm,text="Firewall (UFW) aktivieren und SSH-Port freigeben",variable=v_ssh_ufw)
    c_ssh_ufw.grid(row=r,column=0,columnspan=2,sticky="w",**padd)
    r+=1
    def do_rekey():
        if messagebox.askyesno("Hostkeys neu erzeugen","SSH-Hostkeys neu erzeugen? Clients werden Warnungen sehen."):
            ssh_rekey_hostkeys()
            messagebox.showinfo("OK","SSH-Hostkeys neu erzeugt.")
    ttk.Button(frm,text="SSH-Hostkeys neu erzeugen",command=do_rekey).grid(row=r,column=0,columnspan=2,sticky="w",**padd)

    r+=1; ttk.Separator(frm).grid(row=r,column=0,columnspan=2,sticky="ew",pady=10)

    # Schreibschutz
    r+=1
    c_ro=ttk.Checkbutton(frm,text="Schreibschutz (Overlay) aktivieren",variable=v_ro)
    c_ro.grid(row=r,column=0,columnspan=2,sticky="w",**padd)

    # Buttons
    btns=ttk.Frame(frm); btns.grid(row=r+1,column=0,columnspan=2,sticky="ew",pady=10)
    for c in range(4): btns.columnconfigure(c,weight=1)

    def inputs_set_state(enabled:bool):
        state = ("normal" if enabled else "disabled")
        for w in (e_school,e_url,e_user,e_on,e_off,e_wd,e_reboot,e_selfurl,
                  c_xss,c_uncl,c_auto,c_upnow,c_dist,c_ro,
                  c_ssh,e_ssh_port,c_ssh_pw,txt_ssh_key,c_ssh_ufw):
            try: w.configure(state=state)
            except: pass
        try:
            if enabled: txt_ssh_key.configure(state="normal")
            else: txt_ssh_key.configure(state="disabled")
        except: pass

    def _ssh_info_popup(opt):
        if not opt.ssh.enable:
            return
        ip = _get_first_ip()
        info = f"SSH-Zugang eingerichtet:\n\nHost/IP: {ip}\nPort: {opt.ssh.port}\nUser: {opt.desktop_user}"
        if opt.ssh.pubkey_text:
            info += f"\n\nPublic Key:\n{opt.ssh.pubkey_text.strip()}"
        messagebox.showinfo("SSH-Info (notieren)", info)

    def apply_and_save():
        try:
            if not v_school.get().strip().isdigit(): raise ValueError("Schulnummer numerisch.")
            if not time_ok(v_on.get().strip()) or not time_ok(v_off.get().strip()):
                raise ValueError("Zeiten HH:MM.")
            if v_reboot.get().strip() and not time_ok(v_reboot.get().strip()):
                raise ValueError("Auto-Reboot HH:MM.")
            desk_user=v_user.get().strip() or get_desktop_user()

            # RO-Flow (PW bei Deaktivierung)
            overlay_now=is_overlay_enabled()
            overlay_want=bool(v_ro.get())
            if overlay_now and not overlay_want:
                pw=simpledialog.askstring("Passwort","Schreibschutz aufheben – Passwort:", show="*")
                if pw!=RO_DISABLE_PASSWORD:
                    messagebox.showerror("Fehler","Falsches Passwort. Schreibschutz bleibt aktiv.")
                    v_ro.set(True); return
                if disable_overlay():
                    messagebox.showinfo("Hinweis","Schreibschutz deaktiviert. Neustart erforderlich.")
            if (not overlay_now) and overlay_want:
                if enable_overlay():
                    messagebox.showinfo("Hinweis","Schreibschutz aktiviert. Neustart erforderlich.")

            # SSH Optionen
            try:
                ssh_port=int(v_ssh_port.get().strip())
                if ssh_port<1 or ssh_port>65535: raise ValueError
            except: raise ValueError("SSH-Port ungültig.")
            v_ssh_key.set(txt_ssh_key.get("1.0","end").strip())

            opt=SetupOptions(
                school=v_school.get().strip(),
                url_template=v_url.get().strip(),
                on_time=v_on.get().strip(), off_time=v_off.get().strip(),
                weekdays=v_wd.get().strip(),
                use_xscreensaver=v_xss.get(), use_unclutter=v_uncl.get(),
                enable_auto_updates=v_auto.get(), auto_reboot_time=(v_reboot.get().strip() or None),
                update_now=v_upnow.get(), dist_upgrade=v_dist.get(),
                self_update_url=(v_selfurl.get().strip() or None),
                desktop_user=desk_user, read_only_mode=bool(v_ro.get()),
                ssh=SSHOptions(
                    enable=v_ssh_enable.get(),
                    port=ssh_port,
                    allow_password=v_ssh_pw.get(),
                    pubkey_text=(v_ssh_key.get() or None),
                    ufw_enable=v_ssh_ufw.get(),
                    rekey=False
                )
            )
            save_config(opt); run_setup(opt)
            v_status.set("Gespeichert & angewendet. Neustart empfohlen.")
            # SSH-Info-Popup (damit du es notieren kannst)
            _ssh_info_popup(opt)
            messagebox.showinfo("Erfolg","Konfiguration gespeichert und angewendet.")
        except Exception as e:
            v_status.set(f"Fehler: {e}"); messagebox.showerror("Fehler", str(e))

    def kiosk_test():
        try:
            chrom=get_chromium_binary()
            url=(v_url.get().strip()).format(school_number=v_school.get().strip())
            desk_user=v_user.get().strip() or get_desktop_user()
            sh(f'{chrom} --no-default-browser-check --no-first-run '
               f'--disable-infobars --disable-session-crashed-bubble '
               f'--overscroll-history-navigation=0 --kiosk --app="{url}"',
               check=False, user=desk_user)
            messagebox.showinfo("Hinweis","Kiosk-Test gestartet (Alt+F4 schließen).")
        except Exception as e: messagebox.showerror("Fehler", str(e))

    def reload_cfg():
        state2=load_config(get_desktop_user())
        # Portal
        v_school.set(state2.school); v_url.set(state2.url_template)
        v_user.set(state2.desktop_user); v_on.set(state2.on_time); v_off.set(state2.off_time)
        v_wd.set(state2.weekdays); v_xss.set(state2.use_xscreensaver); v_uncl.set(state2.use_unclutter)
        v_auto.set(state2.enable_auto_updates); v_reboot.set(state2.auto_reboot_time or "")
        v_selfurl.set(state2.self_update_url or ""); v_upnow.set(False); v_dist.set(False)
        # SSH
        v_ssh_enable.set(state2.ssh.enable)
        v_ssh_port.set(str(state2.ssh.port))
        v_ssh_pw.set(state2.ssh.allow_password)
        v_ssh_key.set(state2.ssh.pubkey_text or ""); txt_ssh_key.delete("1.0","end"); txt_ssh_key.insert("1.0", v_ssh_key.get())
        v_ssh_ufw.set(state2.ssh.ufw_enable)
        # RO
        v_ro.set(is_overlay_enabled() or state2.read_only_mode)
        v_status.set("Konfiguration neu geladen.")

    def reboot_now():
        if messagebox.askyesno("Neustart","System jetzt neu starten?"): sh("shutdown -r now", check=False)

    def lock_and_reboot():
        if not v_school.get().strip().isdigit():
            messagebox.showerror("Fehler","Schulnummer numerisch."); return
        if not is_overlay_enabled():
            enable_overlay()
        try: apply_and_save()
        except: pass
        messagebox.showinfo("Info","Neustart – Schreibschutz danach aktiv.")
        sh("shutdown -r now", check=False)

    b_apply=ttk.Button(btns,text="Anwenden & Speichern",command=apply_and_save)
    b_apply.grid(row=0,column=0,sticky="ew",padx=6)
    b_test=ttk.Button(btns,text="Kiosk testen",command=kiosk_test)
    b_test.grid(row=0,column=1,sticky="ew",padx=6)
    b_reload=ttk.Button(btns,text="Config neu laden",command=reload_cfg)
    b_reload.grid(row=0,column=2,sticky="ew",padx=6)
    b_reboot=ttk.Button(btns,text="Neustart",command=reboot_now)
    b_reboot.grid(row=0,column=3,sticky="ew",padx=6)
    b_lock=ttk.Button(frm,text="Fertig & sperren (RO + Neustart)", command=lock_and_reboot)
    b_lock.grid(row=r+2,column=0,columnspan=2,sticky="ew",padx=6,pady=6)

    status=ttk.Label(root,textvariable=v_status,anchor="w"); status.pack(fill="x",padx=10,pady=6)

    # Inputs sperren wenn RO aktiv
    if overlay_now:
        inputs_set_state(False)
        v_status.set("GESCHÜTZT (RO). Zum Aufheben Haken entfernen (Passwort 0825) und neu starten.")
    else:
        inputs_set_state(True)

    def on_ro_toggle(): inputs_set_state(True)
    c_ro.configure(command=on_ro_toggle)

    for c in range(2): frm.columnconfigure(c,weight=1)
    root.mainloop()

# ------------------ CLI / main ------------------

def main():
    require_root()
    parser=argparse.ArgumentParser(description="SchulePI – Kiosk & Portal Setup (mit UI-Default)")
    # Headless/Automation-Flags verfügbar
    parser.add_argument("--apply-config", action="store_true")
    parser.add_argument("--school"); parser.add_argument("--url-template")
    parser.add_argument("--on"); parser.add_argument("--off"); parser.add_argument("--weekdays")
    parser.add_argument("--no-xscreensaver", action="store_true")
    parser.add_argument("--no-unclutter", action="store_true")
    parser.add_argument("--enable-auto-updates", action="store_true")
    parser.add_argument("--auto-reboot")
    parser.add_argument("--update-now", action="store_true")
    parser.add_argument("--dist-upgrade", action="store_true")
    parser.add_argument("--self-update-url")
    parser.add_argument("--desktop-user")
    # Schreibschutz
    parser.add_argument("--enable-ro", action="store_true")
    parser.add_argument("--disable-ro", action="store_true")
    parser.add_argument("--pw")
    # SSH
    parser.add_argument("--enable-ssh", action="store_true")
    parser.add_argument("--disable-ssh", action="store_true")
    parser.add_argument("--ssh-port", type=int)
    parser.add_argument("--ssh-allow-password", action="store_true")
    parser.add_argument("--ssh-disable-password", action="store_true")
    parser.add_argument("--ssh-pubkey")
    parser.add_argument("--ssh-pubkey-file")
    parser.add_argument("--ssh-ufw-enable", action="store_true")
    parser.add_argument("--ssh-rekey", action="store_true")
    # Optional: explizit ohne UI
    parser.add_argument("--no-ui", action="store_true", help="UI nicht starten (reiner CLI-Modus)")

    args = parser.parse_args()

    # UI standardmäßig starten, wenn keine relevanten Flags
    any_flags = any([
        args.apply_config, args.school, args.url_template, args.on, args.off, args.weekdays,
        args.no_xscreensaver, args.no_unclutter, args.enable_auto_updates, args.auto_reboot,
        args.update_now, args.dist_upgrade, args.self_update_url, args.desktop_user,
        args.enable_ro, args.disable_ro, args.pw,
        args.enable_ssh, args.disable_ssh, (args.ssh_port is not None),
        args.ssh_allow_password, args.ssh_disable_password, args.ssh_pubkey, args.ssh_pubkey_file,
        args.ssh_ufw_enable, args.ssh_rekey
    ])

    if not any_flags and not args.no_ui:
        try:
            launch_ui()
        except Exception as e:
            print(f"UI konnte nicht gestartet werden: {e}")
            print("Tipp: Auf Headless-Systemen per CLI arbeiten, z.B.:")
            print("  sudo python3 schulePI.py --no-ui --apply-config --enable-ssh --ssh-port 2222")
        return

    # ===== CLI-Logik =====
    default_user = get_desktop_user()
    opt = load_config(default_user)

    # Schreibschutz zuerst
    if args.enable_ro:
        if not is_overlay_enabled():
            enable_overlay(); print("Schreibschutz aktiviert. Reboot erforderlich.")
        opt.read_only_mode = True
    if args.disable_ro:
        if args.pw != RO_DISABLE_PASSWORD:
            raise SystemExit("Falsches Passwort für --disable-ro.")
        if is_overlay_enabled():
            disable_overlay(); print("Schreibschutz deaktiviert. Reboot erforderlich.")
        opt.read_only_mode = False

    # SSH
    if args.enable_ssh: opt.ssh.enable = True
    if args.disable_ssh: opt.ssh.enable = False
    if args.ssh_port is not None: opt.ssh.port = args.ssh_port
    if args.ssh_allow_password: opt.ssh.allow_password = True
    if args.ssh_disable_password: opt.ssh.allow_password = False
    if args.ssh_pubkey: opt.ssh.pubkey_text = args.ssh_pubkey
    if args.ssh_pubkey_file:
        p = Path(args.ssh_pubkey_file); opt.ssh.pubkey_text = p.read_text("utf-8").strip()
    if args.ssh_ufw_enable: opt.ssh.ufw_enable = True
    if args.ssh_rekey: opt.ssh.rekey = True

    # Portal/Allgemein
    if args.school: opt.school = args.school.strip()
    if args.url_template: opt.url_template = args.url_template.strip()
    if args.on: opt.on_time = args.on.strip()
    if args.off: opt.off_time = args.off.strip()
    if args.weekdays: opt.weekdays = args.weekdays.strip()
    if args.no_xscreensaver: opt.use_xscreensaver = False
    if args.no_unclutter: opt.use_unclutter = False
    if args.enable_auto_updates: opt.enable_auto_updates = True
    if args.auto_reboot:
        if not time_ok(args.auto_reboot): raise SystemExit("--auto-reboot HH:MM")
        opt.auto_reboot_time = args.auto_reboot
    if args.update_now: opt.update_now = True
    if args.dist_upgrade: opt.dist_upgrade = True
    if args.self_update_url: opt.self_update_url = args.self_update_url.strip()
    if args.desktop_user: opt.desktop_user = args.desktop_user.strip()

    if args.apply_config or any_flags:
        if not opt.school or not opt.school.isdigit(): raise SystemExit("Ungültige Schulnummer.")
        if not time_ok(opt.on_time) or not time_ok(opt.off_time): raise SystemExit("AN/AUS-Zeit HH:MM.")
        if opt.auto_reboot_time and not time_ok(opt.auto_reboot_time): raise SystemExit("Auto-Reboot HH:MM.")
        save_config(opt); run_setup(opt)
        # SSH-Info kommt automatisch aus apply_ssh_settings()
    else:
        print("Keine Aktion. Beispiele:")
        print("  sudo python3 schulePI.py               # UI starten")
        print("  sudo python3 schulePI.py --no-ui --apply-config")

if __name__=="__main__":
    main()
