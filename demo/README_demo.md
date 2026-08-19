# Demo runbook — Northwind portal vs attack-detector

Show a real website degrade under attack, then flip enforce and watch the
detector protect it. Everything is real: real nginx, real attacks, real nftables.

## Machines
- TARGET  192.168.50.10  : nginx (Northwind portal) + engine + API (systemd services)
- ATTACKER 192.168.50.11 : runs the demo services (probe, launcher, page)
- YOU                    : browser, over two SSH tunnels

## One-time setup
On the target (once): deploy the portal.
    cd ~/attack-detector && sudo bash demo/deploy_site.sh
On the attacker (once): install attack tools.
    sudo apt install -y sshpass apache2-utils slowhttptest python3

## Every time — 3 steps

### 1. Attacker: start all demo services (one terminal)
    ssh <attacker-user>@localhost -p 2223
    cd ~/attack-detector
    bash demo/start_demo.sh
Leave it running. It prints a health check and the exact tunnel commands.
Ctrl+C stops all three services cleanly.

### 2. Your workstation: open two tunnels (two terminals, leave both open)
    ssh -L 8070:127.0.0.1:8070 -L 8080:127.0.0.1:8080 -L 8090:127.0.0.1:8090 <attacker-user>@localhost -p 2223
    ssh -L 8787:127.0.0.1:8787 -L 8088:127.0.0.1:80 <target-user>@localhost -p 2222

### 3. Browser
Open http://127.0.0.1:8070/demo.html
The connection strip at the top shows probe/launcher/detector status. Only one
thing needs pasting: the detector API token, in the Connections row.
    token:  sudo cat /etc/attack-detector/api.env   (on the target)
Paste it into "API token", click save. All three should read "connected".
The portal URL defaults to http://127.0.0.1:8088/ (the live Northwind site via the
target tunnel). You should see the real login page at the top of the demo screen.

## The demo (in clicks)
1. Site reads operational, chart flat. Click "request flood (HTTP)".
   -> chart climbs, verdict goes degraded, a request_flood alert appears.
2. Click "enforce". Click "request flood" again.
   -> engine rate-limits the attacker; chart stays flatter, limited count rises.
   That contrast is the whole point.
3. "connection flood (Slowloris)" is the dramatic one: the real login page at the
   top stalls and shows "site not responding", the chart spikes, an alert fires.
   Flip enforce -> the engine blocks the holding IP and the portal loads again.
4. "brute force (SSH)" shows the auth-log path: alert appears, enforce blocks it.
Every attack auto-stops after 30s. "stop" ends it early.

## If a panel says offline
The connection strip tells you which one. Check:
- probe/launcher/page offline  -> is start_demo.sh still running on the attacker?
                                  is the attacker tunnel (2223) open?
- detector offline             -> is the target tunnel (8787 -> 2222) open?
                                  did you paste + save the API token?
Logs on the attacker: /tmp/demo_probe.log, /tmp/demo_launcher.log, /tmp/demo_page.log

## Making the site actually stall (small lab)
nginx is resilient; one attacker VM may not overwhelm it at normal capacity. Scale
the victim down to match the lab attacker (real attack, real defense, victim sized
to the lab):

    # on the TARGET, once, before the demo:
    sudo bash demo/nginx_demo_limits.sh
    # restore afterwards:
    sudo bash demo/nginx_demo_limits.sh --restore

With this applied, a 1500-connection Slowloris exhausts nginx: in monitor the
portal stalls and the overlay shows; in enforce the engine blocks the attacker and
the portal recovers.

## Run of show (what to click, what to say)
1. Show the portal at the top loading normally. "This is the company login portal."
2. Detector on monitor. "Right now the detector is watching but not blocking."
3. Click "connection flood (Slowloris)". Wait ~10s.
   "An attacker is opening thousands of connections and holding them open."
   -> portal shows "site not responding", chart climbs, alert fires.
   "The site is down for real users, and the detector has flagged it."
4. Point at the alert + the attacker IP. "It knows who and how."
5. Click "enforce". "Now we let it act."
   -> attacker IP appears in the blocked list; portal reloads; response time drops.
   "The engine blocked the source. The site is back. The attack is still running,
    but it can no longer reach us."
6. Click "stop". Restore: sudo bash demo/nginx_demo_limits.sh --restore

## Fragile app server + "never crashes in enforce" (crash demo)
nginx is too tough to crash on a small lab, so the demo uses a deliberately
fragile app server that genuinely goes down under a connection-exhaustion attack
and recovers when the attacker is blocked.

On the TARGET, run the app (serves the Northwind portal on :8000):
    cd ~/attack-detector
    bash demo/app/run_app.sh              # 8 workers
    # fewer workers crash faster:  WORKERS=6 bash demo/app/run_app.sh

TUNING so enforce reliably protects it (the important part):
- The app saturates at roughly its worker count in held connections.
- Set the detector's conn_threshold BELOW that, and sample fast, so the block
  lands before saturation. In /etc/attack-detector/config.yaml on the target:
      conn_threshold: 20        # below the app's worker count
      connstate_interval: 2     # sample every 2s
  then: sudo systemctl restart attack-detector
- Rule of thumb: conn_threshold < workers, and the attack should take a few
  seconds (not instant) to exhaust the app. The app_conn_exhaust attack ramps at
  ~50 conns/10s, giving the 2s sampler time to catch it around 20-40 conns.

The demo:
1. Detector on MONITOR. Tap "Denial of service - connection exhaustion".
   -> within a few seconds the app's workers are exhausted; the page shows the
      site "not responding". Real crash, no cap.
2. Tap "enforce". Tap the same attack again.
   -> the engine blocks the attacker within ~2s, before the workers saturate.
      The app stays up the whole time. Same attack, never falls.

## Audience page vs technical page
- demo/show.html  : audience view - just the live site, 3 plain-named attack
  buttons, and the defense toggle. No chart. This is what you screen/hand out.
- demo/demo.html  : technical view - health chart, alert feed, detector internals.
  Keep this for yourself.

## Phone control
See demo/PHONE_SETUP.md - forward the ports on your PC and open show.html from
your phone using your PC's LAN IP.
