def main():
    require_root()
    import argparse
    parser = argparse.ArgumentParser(description="SchulePI – Kiosk & Portal Setup")
    # Headless/Automation-Flags bleiben verfügbar
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

    # Wenn KEINE sinnvollen Flags gesetzt sind und nicht --no-ui: UI starten.
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
        # Standard: UI hochfahren
        try:
            launch_ui()
        except Exception as e:
            # Fallback-Hinweis für Headless-Systeme
            print(f"UI konnte nicht gestartet werden: {e}")
            print("Tipp: Auf Headless-Systemen per CLI arbeiten, z.B.:")
            print("  sudo python3 schulePI.py --apply-config --enable-ssh --ssh-port 2222")
        return

    # ===== Ab hier: bisherige CLI-Logik (unverändert) =====
    default_user = get_desktop_user()
    opt = load_config(default_user)

    # Schreibschutz zuerst
    if args.enable_ro:
        if not is_overlay_enabled():
            enable_overlay(); print("Schreibschutz aktiviert. Reboot erforderlich.")
        opt.read_only_mode = True
    if args.disable_ro:
        if args.pw != "0825":
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
        # Falls jemand --no-ui ohne weitere Flags nutzt, kurze Hilfe zeigen
        print("Keine Aktion. Beispiele:")
        print("  sudo python3 schulePI.py               # UI starten")
        print("  sudo python3 schulePI.py --no-ui --apply-config")
