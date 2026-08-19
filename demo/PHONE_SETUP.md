# Controlling the demo from your phone

Your phone is a remote control. Tapping a button tells the launcher (on the
attacker VM) to fire a real attack from that VM at the target. The phone never
attacks; it just presses the button. So the phone must be able to reach the
demo page and the launcher over your network.

## The clean way: VirtualBox port-forwarding on your PC (same wifi)

Phone and PC on the same wifi. Add these NAT port-forwards so your PC's LAN IP
exposes the demo, and VirtualBox routes them to the attacker VM.

VirtualBox Manager -> attacker VM -> Settings -> Network -> Adapter (NAT) ->
Advanced -> Port Forwarding. Add:

    Name        Host IP     Host Port   Guest IP        Guest Port
    demo-page   0.0.0.0     8070        (attacker IP)   8070
    launcher    0.0.0.0     8090        (attacker IP)   8090
    app-probe   0.0.0.0     8080        (attacker IP)   8080

For the target VM (same place, target's NAT adapter), forward the app + API:

    Name        Host IP     Host Port   Guest IP        Guest Port
    app         0.0.0.0     8000        (target IP)     8000
    detector    0.0.0.0     8787        (target IP)     8787

Leave Guest IP blank if VirtualBox complains; NAT will still route to the VM.

Find your PC's LAN IP (Windows PowerShell):

    ipconfig | findstr IPv4

Say it's 192.168.1.50. On your phone's browser, open:

    http://192.168.1.50:8070/show.html

Open the Setup panel (bottom of the page) once and set every URL to use your
PC's IP instead of 127.0.0.1, e.g.:

    site        http://192.168.1.50:8000/
    appstate    http://192.168.1.50:8000/appstate
    launcher    http://192.168.1.50:8090
    detector    http://192.168.1.50:8787/api
    launcher token   pickatoken
    API token        (from /etc/attack-detector/api.env on the target)

Tap save. The page now drives everything through your PC's IP, which VirtualBox
forwards into the VMs.

## Security note
Exposing the launcher beyond localhost means the token is the lock. The launcher
refuses to start on a non-localhost bind without a token, only ever targets the
hardcoded lab IP, and auto-stops every attack after 30s. Keep the token private
and only run this on a network you trust (your home wifi, not public).
