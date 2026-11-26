# NetWatch

NetWatch is a desktop application for **your own computer**. It watches that computer for incoming pings and for local man-in-the-middle signs. It is a separate tool and does not change PhishGuard.

It is not a service inside a remote VM. A copy running somewhere else cannot see your LAN. Unzip it on the PC you want to protect and open the window there.

This is not a file antivirus and it is not Wireshark. Wireshark shows every packet. NetWatch only raises the events that look like a "are you up?" check or a route hijack on the local network.

## What the window shows

- New ICMP echo requests (pings) since the window opened. Run it as administrator to also see who sent them.
- A change of the router MAC after you confirm it. That is the usual picture of ARP spoofing.
- The confirmed router MAC appearing on another address.
- Two MAC addresses for one IP, or many MAC addresses changing together.
- An ICMP redirect: a device telling this computer to send traffic somewhere else.

The simulation buttons change only the screen. They do not send a ping and they do not run an attack.

## What Pin the MAC does

**Pin the MAC** writes a static ARP entry only for the router IP, and only for the MAC you confirmed. It needs administrator rights. It lasts until reboot or until you press **Forget it**.

If the MAC no longer matches the one you confirmed, pinning writes the old one back. It does not accept the new MAC unless you press **Accept the new MAC** after checking it on the device.

## What it does not stop

- File viruses and malware.
- An attack at your provider.
- A fake Wi-Fi network that is itself the router. The MAC you see then belongs to that router.
- Someone who poisoned only the router's ARP table and not this computer's.
- Anything hidden inside HTTPS.

Without administrator rights you can see that pings arrived, not the address that sent them.

## Windows application

Download `release/NetWatch-windows.zip`, unzip it on the Windows PC, and double-click `NetWatch.exe`.

To see the sender of a ping, or to pin the router MAC, right-click `NetWatch.exe` and choose **Run as administrator**.

Rebuild that zip from Linux:

```bash
bash packaging/windows/build.sh
```

## Run from source

```bash
cd netwatch
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
netwatch
```

`netwatch` opens the desktop window on this computer. On Linux that needs `python3-tk`.

One reading, without a window:

```bash
netwatch --once
```

A simulated ping and MITM, with no packets sent:

```bash
netwatch --demo
```

## Tests

```bash
pytest -q
```
