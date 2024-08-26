import os
import time
import sys
from scapy.all import *
from collections import defaultdict
import threading
from colorama import Fore, Style, init
import logging
import argparse

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Initialize colorama
init(autoreset=True)

# Dictionary to store access points, devices, and associations
networks = defaultdict(dict)
devices_with_ap = defaultdict(dict)
devices_without_ap = defaultdict(dict)
other_devices = defaultdict(dict)
associations = defaultdict(set)

def change_channel(interface, sleep_duration):
    """Function to change the Wi-Fi channel periodically for channel hopping."""
    ch = 1
    while True:
        try:
            os.system(f"iwconfig {interface} channel {ch}")
            ch = ch % 13 + 1  # Channels 1-14 (2.4 GHz)
            time.sleep(sleep_duration)  # Hop every sleep_duration seconds
        except Exception as e:
            print(f"An error occurred while changing channel: {e}")

def packet_handler(packet):
    """Function to handle each captured packet."""
    try:
        if packet.haslayer(Dot11):
            # Process beacon frames (from APs)
            if packet.type == 0 and packet.subtype == 8:
                process_beacon_frame(packet)
            # Process probe requests (from devices)
            elif packet.type == 0 and packet.subtype == 4:
                process_probe_request(packet)
            # Process data frames (from associated devices)
            elif packet.type == 2:
                process_data_frame(packet)

        # Clear terminal and print the updated tables
        os.system('clear')
        print_network_table(networks)
        print_associated_devices(devices_with_ap, networks)
        print_non_associated_devices(devices_without_ap)
        print_other_devices(other_devices)

    except AttributeError:
        pass
    except Exception as e:
        print(f"An error occurred: {e}")

def process_beacon_frame(packet):
    ssid = packet.info.decode('utf-8', errors='ignore')
    bssid = packet.addr2
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
    encryption = _get_encryption_type(packet)
    # Extract channel information from the Dot11Elt layers
    channel = 'Unknown'
    if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
        elements = packet[Dot11Beacon].network_stats()  # This method gives you network stats including the channel
        channel = elements.get("channel", "Unknown")
    networks[bssid] = {'SSID': ssid, 'Signal': dbm_signal, 'Channel': channel, 'Encryption': encryption}

def process_probe_request(packet):
    mac = packet.addr2
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
    probe_ssid = packet.info.decode('utf-8', errors='ignore') if packet.info else 'N/A'
    if probe_ssid == 'N/A':
        other_devices[mac] = {'Signal': dbm_signal, 'Probe SSID': probe_ssid}
    else:
        devices_without_ap[mac] = {'Signal': dbm_signal, 'Probe SSID': probe_ssid}

def process_data_frame(packet):
    bssid = packet.addr1
    client_mac = packet.addr2
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
    if bssid in networks:
        associations[bssid].add(client_mac)
        devices_with_ap[client_mac] = {'Signal': dbm_signal, 'Associated AP': bssid}
        if client_mac in devices_without_ap:
            del devices_without_ap[client_mac]
        if client_mac in other_devices:
            del other_devices[client_mac]

def _get_encryption_type(packet):
    """Function to determine the encryption type of a network."""
    encryption = "Open"  # Default to 'Open' if no encryption type is detected
    if packet.haslayer(Dot11Elt):
        p = packet[Dot11Elt]
        while isinstance(p, Dot11Elt):
            if p.ID == 48:
                encryption = "WPA2"
            elif p.ID == 221 and p.info.startswith(b'\x00\x50\xf2\x01'):
                encryption = "WPA"
            elif p.ID == 221 and p.info.startswith(b'\x00\x0f\xac\x04'):
                encryption = "WPA3"
            p = p.payload
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
        if 'privacy' in cap and encryption == "Open":
            encryption = "WEP"
    return encryption

def print_network_table(networks):
    max_ssid_len = max((len(info['SSID']) for info in networks.values()), default=0) + 5
    total_width = 17 + max_ssid_len + 6 + 8 + 11  # Adjust width for channel column
    print(f"{'BSSID':<17} | {'SSID':<{max_ssid_len-5}} | {'Signal':<6} | {'Channel':<8}| {'Encryption':<10}")
    print("-" * (total_width + 5))
    for bssid, info in networks.items():
        ssid_color = Fore.LIGHTGREEN_EX
        encryption_color = Fore.WHITE
        if info['Encryption'] == "Open":
            encryption_color = Fore.LIGHTGREEN_EX
        elif info['Encryption'] == "WPA3":
            encryption_color = Fore.RED
        elif info['Encryption'] == "WPA2":
            encryption_color = Fore.YELLOW
        elif info['Encryption'] == "WPA":
            encryption_color = Fore.LIGHTYELLOW_EX
        print(f"{Fore.LIGHTBLUE_EX + bssid:<17}" + Fore.WHITE + " | " +
              f"{ssid_color + info['SSID']:<{max_ssid_len}}" + Fore.WHITE + " | " +
              f"{info['Signal']:<6} | {Fore.WHITE + str(info['Channel']):<12} | {encryption_color + info['Encryption']:<10}")

def print_associated_devices(devices_with_ap, networks):
    max_ap_len = max((len(networks[info['Associated AP']]['SSID']) for info in devices_with_ap.values() if info['Associated AP'] in networks), default=10) + 5
    if (17 + 6 + max_ap_len)+1 <= 41:
        header_len = 41
    else:
        header_len = (17 + 6 + max_ap_len)+1
    print("\n")
    print(f"{'MAC':<17} | {'Signal':<6} | {'Associated AP':<{max_ap_len}}")
    print("-" * (header_len+1))
    for mac, info in devices_with_ap.items():
        associated_ap_display = networks[info['Associated AP']]['SSID'] if info['Associated AP'] in networks else 'N/A'
        print(f"{Fore.LIGHTBLUE_EX + mac:<17}" + Fore.WHITE + " | " + f"{info['Signal']:<6}" + Fore.WHITE + " | " + f"{Fore.LIGHTGREEN_EX + associated_ap_display:<{max_ap_len}}")

def print_non_associated_devices(devices_without_ap):
    max_probe_len = max((len(info['Probe SSID']) for info in devices_without_ap.values()), default=10) + 5
    header_len = 17 + 6 + max_probe_len
    print("\n")
    print(f"{'MAC':<17} | {'Signal':<6} | {'Probe SSID':<{max_probe_len}}")
    print("-" * (header_len+1))
    for mac, info in devices_without_ap.items():
        probe_color = Fore.RED if info['Probe SSID'] == 'N/A' else Fore.YELLOW
        print(f"{Fore.LIGHTBLUE_EX + mac:<17}" + Fore.WHITE + " | " + f"{info['Signal']:<6} | {probe_color + info['Probe SSID']:<{max_probe_len}}")

def print_other_devices(other_devices):
    print("\n")
    print(f"{'MAC':<17} | {'Signal':<6}")
    print("-" * 26)
    for mac, info in other_devices.items():
        print(f"{Fore.LIGHTBLUE_EX + mac:<17}" + Fore.WHITE + f" | {info['Signal']:<6}")

def start_sniffing(interface):
    """Function to start sniffing and handle network errors."""
    while True:
        try:
            sniff(iface=interface, prn=packet_handler)
        except KeyboardInterrupt:
            print("\nUser interrupted the script.")
            break
        except OSError as e:
            if "Network is down" in str(e):
                time.sleep(1)  # Wait a bit before restarting
                continue  # Restart sniffing
            else:
                print(f"An OS error occurred: {e}")
                break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wi-Fi Sniffer")
    parser.add_argument("interface", help="The network interface to use, e.g., wlan0")
    parser.add_argument("-s", "--sleep", type=float, default=2, help="Sleep duration between channel hops, default is 2 seconds")
    
    args = parser.parse_args()
    
    print(f"Listening for packets on {args.interface} with a channel hopping sleep of {args.sleep} seconds...")

    channel_hop_thread = threading.Thread(target=change_channel, args=(args.interface, args.sleep))
    channel_hop_thread.daemon = True
    channel_hop_thread.start()

    start_sniffing(args.interface)
