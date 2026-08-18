# Installing attack-detector

A one-command install that runs the engine and dashboard as systemd services on
Ubuntu. Tested on Ubuntu Server 24.04.

## Install

From the repo root on the target server:

    sudo bash deploy/install.sh

This:
- installs python3, nftables, and flask (via apt)
- copies the app to /opt/attack-detector
- writes config to /etc/attack-detector/config.yaml (mode: monitor)
- generates an API token in /etc/attack-detector/api.env (port 8787)
- installs and starts two services: attack-detector and attack-detector-api

Both run as root: the engine needs it for nftables, and running both as the same
identity means they share the runtime files in /var/lib/attack-detector, so there
is no permission mismatch between them.

## Before you use enforce mode

Edit the config and set your admin IP so enforce cannot lock you out:

    sudo nano /etc/attack-detector/config.yaml
    #   admin_allowlist: ["10.0.2.2"]   <- your admin path (SSH via NAT = 10.0.2.2)
    sudo systemctl restart attack-detector

Enforce mode refuses to start with an empty allowlist, so this is required
before blocking can be armed.

## Check it is running

    systemctl status attack-detector
    systemctl status attack-detector-api

Both should read active (running). They start on boot and restart on failure.

## Open the dashboard

The API is bound to localhost. Reach it over an SSH tunnel from your machine:

    ssh -L 8787:127.0.0.1:8787 <user>@<host>
    # then open http://127.0.0.1:8787/ in your browser

Get the token to paste into the dashboard's Access box:

    sudo cat /etc/attack-detector/api.env

## Control from the command line

    VAR=/var/lib/attack-detector
    sudo python3 -m attack_detector.ctl --status $VAR/status.json status
    # mode changes: edit the dashboard, or:
    echo '{"mode":"enforce"}' | sudo tee $VAR/control.json

## Logs

    journalctl -u attack-detector -f          # engine
    journalctl -u attack-detector-api -f      # api
    sudo tail -f /var/lib/attack-detector/alerts.log

## Uninstall

    sudo bash deploy/uninstall.sh
    # this stops the services, flushes the firewall table, and removes /opt.
    # config, token, and logs are left in /etc and /var/lib; remove by hand for
    # a full wipe.
