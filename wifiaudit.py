import os
from os import name, system
import time
import sys
from scapy.all import *
from collections import defaultdict
import threading
from colorama import Fore, init
import logging
import argparse
import re
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from mac_vendor_lookup import MacLookup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logging.getLogger().setLevel(logging.ERROR)

# Initialize colorama
init(autoreset=True)

# Dictionary to store access points, devices, and associations
networks = defaultdict(lambda: {'Beacons': 0, 'Data': 0, 'Data Rate': 0, 'Last Data Count': 0, 'Last Update Time': time.time(), 'Vendor': '-', 'Hidden': False})
devices_with_ap = defaultdict(dict)
devices_without_ap = defaultdict(lambda: {'Signal': 'N/A', 'Probe SSID': set(), 'Vendor': '-', 'Randomized': False})
other_devices = defaultdict(dict)
associations = defaultdict(set)

packet_queue = Queue()
mac_lookup_queue = Queue()

# Global variable to control print timing
last_print_time = time.time()

# Ensure the data file exists at the start of the script
data_file_path = 'wifiaudit_data.txt'
if not os.path.exists(data_file_path):
    open(data_file_path, 'w').close()

def sanitize_interface(interface):
    """Sanitize the network interface input to prevent injection attacks."""
    if re.match(r'^[a-zA-Z0-9_-]+$', interface):
        return interface
    logging.error(f"Invalid interface name provided: {interface}")
    sys.exit(1)

def change_channel(interface, sleep_duration):
    """Function to change the Wi-Fi channel periodically for channel hopping."""
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        ch = ch % 14 + 1  # Channels 1-14 (2.4 GHz)
        time.sleep(sleep_duration)  # Hop every sleep_duration seconds

def set_channel(interface, channel):
    """Set the interface to a specific Wi-Fi channel."""
    os.system(f"iwconfig {interface} channel {channel}")
    logging.info(f"Listening on channel {channel}...")

def packet_handler(packet):
    """Function to handle each captured packet."""
    try:
        if args.mac and (packet.addr1 != args.mac and packet.addr2 != args.mac):
            return
        packet_queue.put(packet)
    except Exception as e:
        logging.error(f"An error occurred while putting packet to queue: {e}")

def process_packets():
    """Function to process packets from the queue."""
    global last_print_time
    while True:
        packet = packet_queue.get()
        try:
            if packet.haslayer(Dot11): # type: ignore
                if packet.type == 0 and packet.subtype == 8:
                    process_beacon_frame(packet)
                elif packet.type == 0 and packet.subtype == 4:
                    process_probe_request(packet)
                elif packet.type == 2:
                    process_data_frame(packet)

            current_time = time.time()
            if current_time - last_print_time >= 1:
                update_data_rates()
                print_and_log_network_data()
                last_print_time = current_time
        except AttributeError:
            pass
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            packet_queue.task_done()

def process_beacon_frame(packet):
    ssid = packet.info.decode('utf-8', errors='ignore') if packet.info else ''
    bssid = packet.addr2
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
    encryption = _get_encryption_type(packet)

    networks[bssid]['Beacons'] += 1

    elements = packet[Dot11Beacon].network_stats() if packet.haslayer(Dot11Beacon) else {}  # type: ignore
    channel = elements.get("channel", "Unknown")
    frequency = calculate_frequency(channel)  # Calculate frequency based on channel

    is_randomized = check_randomized_mac(bssid)

    # Check if the SSID is hidden (empty)
    if ssid == '':
        # Find the Dot11Elt with ID 0 for SSID
        ssid_element = packet.getlayer(Dot11Elt, ID=0)
        if ssid_element and hasattr(ssid_element, 'len'):
            ssid_length = ssid_element.len  # Use the length field of the Dot11Elt layer
            ssid = f"<length: {ssid_length}>"
        else:
            ssid = "<length: 0>"
        networks[bssid]['Hidden'] = True

    if bssid not in networks:
        networks[bssid].update({
            'SSID': ssid,
            'Signal': dbm_signal,
            'Channel': channel,
            'Frequency': frequency,
            'Encryption': encryption,
            'Randomized': is_randomized
        })
        mac_lookup_queue.put(bssid)
    else:
        networks[bssid].update({
            'SSID': ssid,
            'Signal': dbm_signal,
            'Channel': channel,
            'Frequency': frequency,
            'Encryption': encryption,
            'Randomized': is_randomized  # Ensure Randomized status is updated
        })
        if networks[bssid]['Vendor'] == '-':
            mac_lookup_queue.put(bssid)

    remove_bssid_from_other_tables(bssid)

def remove_bssid_from_other_tables(bssid):
    """Remove BSSID from other tables to maintain data integrity."""
    for table in [devices_with_ap, devices_without_ap, other_devices]:
        if bssid in table:
            del table[bssid]

def process_data_frame(packet):
    bssid = packet.addr1  # BSSID of the AP
    client_mac = packet.addr2  # MAC address of the client device
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'

    is_randomized = check_randomized_mac(client_mac)

    if bssid in networks:
        associations[bssid].add(client_mac)
        networks[bssid]['Data'] += 1

        if bssid and bssid != 'N/A' and client_mac not in networks and client_mac not in devices_with_ap:
            devices_with_ap[client_mac] = {'Signal': dbm_signal, 'Associated AP': bssid, 'Vendor': '-', 'Randomized': is_randomized}
            mac_lookup_queue.put(client_mac)

        remove_mac_from_other_tables(client_mac)

    else:
        if client_mac not in networks and client_mac not in devices_with_ap:
            if client_mac not in other_devices:
                other_devices[client_mac] = {'Signal': dbm_signal, 'Vendor': '-', 'Randomized': is_randomized}
                mac_lookup_queue.put(client_mac)

def remove_mac_from_other_tables(client_mac):
    """Ensure the client MAC is not present in devices_without_ap or other_devices."""
    for table in [devices_without_ap, other_devices]:
        if client_mac in table:
            del table[client_mac]

def update_data_rates():
    """Update the #/s for each network."""
    current_time = time.time()
    for bssid, info in networks.items():
        time_diff = current_time - info['Last Update Time']
        if time_diff > 0:
            data_diff = info['Data'] - info['Last Data Count']
            info['Data Rate'] = data_diff / time_diff
            info['Last Data Count'] = info['Data']
            info['Last Update Time'] = current_time

def calculate_frequency(channel):
    """Calculate frequency based on channel and convert to GHz."""
    try:
        channel = int(channel)
    except ValueError:
        return "Unknown"
    
    if 1 <= channel <= 14:
        return '2.4 GHz'
    elif 36 <= channel <= 165:
        return '5 GHz'
    return "Unknown"

def find_channel_for_mac(interface, target_mac):
    """Continuously find the channel for a specific MAC address by scanning all channels."""
    found_channel = None

    def packet_callback(packet):
        nonlocal found_channel
        if packet.haslayer(Dot11):
            if packet.addr2 == target_mac or packet.addr1 == target_mac:
                elements = packet[Dot11Beacon].network_stats()  # type: ignore
                found_channel = elements.get("channel", None)
                return True  # Stop sniffing when found

    while not found_channel:
        for ch in range(1, 15):


            set_channel(interface, ch)
            clear()
            print(f"Scanning for {target_mac} on channel {ch}...")
            sniff(iface=interface, prn=packet_callback, stop_filter=lambda x: found_channel is not None, timeout=0.2, store=0)

    return found_channel

def process_probe_request(packet):
    mac = packet.addr2
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
    probe_ssid = packet.info.decode('utf-8', errors='ignore') if packet.info else 'N/A'

    is_randomized = check_randomized_mac(mac)

    if mac not in networks and mac not in devices_with_ap:
        if mac not in devices_without_ap and mac not in other_devices:
            if probe_ssid == 'N/A':
                other_devices[mac] = {'Signal': dbm_signal, 'Vendor': '-', 'Randomized': is_randomized}
            else:
                devices_without_ap[mac] = {
                    'Signal': dbm_signal,
                    'Probe SSID': {probe_ssid},
                    'Vendor': '-',
                    'Randomized': is_randomized
                }
            mac_lookup_queue.put(mac)
        else:
            if mac in devices_without_ap:
                devices_without_ap[mac]['Signal'] = dbm_signal
                if probe_ssid != 'N/A':
                    devices_without_ap[mac]['Probe SSID'].add(probe_ssid)
            elif mac in other_devices and probe_ssid == 'N/A':
                other_devices[mac].update({'Signal': dbm_signal})

def check_randomized_mac(mac):
    """Check if the MAC address is randomized."""
    return mac[1].upper() in ['A', 'E', '2', '6']

def _get_encryption_type(packet):
    """Function to determine the encryption type of a network."""
    encryption = "Open"
    is_wpa, is_wpa2, is_wpa3 = False, False, False

    if packet.haslayer(Dot11Elt): # type: ignore
        p = packet[Dot11Elt] # type: ignore
        while isinstance(p, Dot11Elt): # type: ignore
            if p.ID == 48:
                is_wpa2 = True
            elif p.ID == 221:
                if p.info.startswith(b'\x00\x50\xf2\x01'):
                    is_wpa = True
                elif p.info.startswith(b'\x00\x0f\xac\x04'):
                    is_wpa3 = True
            p = p.payload
        
        if is_wpa3:
            encryption = "WPA3"
        elif is_wpa2:
            encryption = "WPA2"
        elif is_wpa:
            encryption = "WPA"
        elif 'privacy' in packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+'):
            encryption = "WEP"
    
    return encryption

def print_and_log_network_data():
    """Function to print all network data in a formatted way and log it to a file."""
    clear()

    # Sort networks by SSID for consistent order
    sorted_networks = dict(sorted(networks.items(), key=lambda item: item[1].get('SSID', '')))

    # Print to terminal with colors
    print_table(sorted_networks, ['BSSID', 'SSID', 'Signal', 'Channel', 'Frequency', 'Encryption', 'Beacons', 'Data', '#/s', 'Vendor'], format_network_row, color=True)
    print_table(devices_with_ap, ['MAC', 'Signal', 'Associated AP', 'Vendor'], format_associated_device_row, color=True)
    print_table(devices_without_ap, ['MAC', 'Signal', 'Probe SSIDs', 'Vendor'], format_non_associated_device_row, color=True)
    print_table(other_devices, ['MAC', 'Signal', 'Vendor'], format_other_device_row, color=True)

    # Write to file without colors
    with open(data_file_path, 'w') as f:
        print_table(sorted_networks, ['BSSID', 'SSID', 'Signal', 'Channel', 'Frequency', 'Encryption', 'Beacons', 'Data', '#/s', 'Vendor'], format_network_row, file=f, color=False)
        print_table(devices_with_ap, ['MAC', 'Signal', 'Associated AP', 'Vendor'], format_associated_device_row, file=f, color=False)
        print_table(devices_without_ap, ['MAC', 'Signal', 'Probe SSIDs', 'Vendor'], format_non_associated_device_row, file=f, color=False)
        print_table(other_devices, ['MAC', 'Signal', 'Vendor'], format_other_device_row, file=f, color=False)

def format_network_row(bssid, info, color=True):
    """Format rows for network data, ensuring color codes are only included when color is True."""
    vendor_display = info.get('Vendor', '-')
    mac_display = f"{bssid}{(Fore.YELLOW + ' *' if info.get('Randomized', False) else '')}"

    ssid_display = info.get('SSID', '')
    if color:
        vendor_color = Fore.LIGHTMAGENTA_EX if vendor_display == 'Unknown' else Fore.WHITE if vendor_display == '-' else Fore.LIGHTMAGENTA_EX
        mac_color = Fore.LIGHTBLUE_EX  # Base color for the MAC address, without the asterisk
        ssid_color = Fore.LIGHTCYAN_EX if info.get('Hidden', False) else Fore.LIGHTGREEN_EX
        return [
            mac_color + bssid + Fore.RESET + (Fore.YELLOW + ' *' + Fore.RESET if info.get('Randomized', False) else ''),
            ssid_color + ssid_display + Fore.RESET,
            Fore.WHITE + ' ' + str(info.get('Signal', 'N/A')) + Fore.RESET,
            Fore.WHITE + '   ' + str(info.get('Channel', 'Unknown')) + Fore.RESET,
            Fore.WHITE + ' ' + str(info.get('Frequency', 'Unknown')) + Fore.RESET,
            get_encryption_color(info.get('Encryption', 'Open')) + '   ' + info.get('Encryption', 'Open') + Fore.RESET,
            Fore.WHITE + '  ' + str(info.get('Beacons', 0)) + Fore.RESET,
            Fore.WHITE + ' ' + str(info.get('Data', 0)) + Fore.RESET,
            Fore.WHITE + f"{info.get('Data Rate', 0):.2f}" + Fore.RESET,
            vendor_color + ('-' if vendor_display == 'Unknown' else vendor_display) + Fore.RESET
        ]
    else:
        return [
            mac_display,
            ssid_display,
            str(info.get('Signal', 'N/A')),
            str(info.get('Channel', 'Unknown')),
            str(info.get('Frequency', 'Unknown')),
            info.get('Encryption', 'Open'),
            str(info.get('Beacons', 0)),
            str(info.get('Data', 0)),
            f"{info.get('Data Rate', 0):.2f}",
            '-' if vendor_display == 'Unknown' else vendor_display
        ]

def format_associated_device_row(mac, info, color=True):
    """Format rows for associated devices, ensuring color codes are only included when color is True."""
    vendor_display = info.get('Vendor', '-')
    mac_display = f"{mac}{(Fore.YELLOW + ' *' if info.get('Randomized', False) else '')}"

    associated_ap_display = networks[info['Associated AP']]['SSID'] if info['Associated AP'] in networks else 'N/A'
    if color:
        vendor_color = Fore.LIGHTMAGENTA_EX if vendor_display == 'Unknown' else Fore.WHITE if vendor_display == '-' else Fore.LIGHTMAGENTA_EX
        mac_color = Fore.LIGHTBLUE_EX
        ap_color = Fore.LIGHTGREEN_EX
        return [
            mac_color + mac_display + Fore.RESET,
            Fore.WHITE + ' ' + str(info.get('Signal', 'N/A')) + Fore.RESET,
            ap_color + associated_ap_display + Fore.RESET,
            vendor_color + vendor_display + Fore.RESET
        ]
    else:
        return [
            mac_display,
            str(info.get('Signal', 'N/A')),
            associated_ap_display,
            '-' if vendor_display == 'Unknown' else vendor_display
        ]

def format_non_associated_device_row(mac, info, color=True):
    """Format rows for non-associated devices, ensuring color codes are only included when color is True."""
    vendor_display = info.get('Vendor', '-')
    mac_display = f"{mac}{(Fore.YELLOW + ' *' if info.get('Randomized', False) else '')}"
    probe_ssids = ', '.join(info['Probe SSID'])
    
    if color:
        vendor_color = Fore.LIGHTMAGENTA_EX if vendor_display == 'Unknown' else Fore.WHITE if vendor_display == '-' else Fore.LIGHTMAGENTA_EX
        probe_color = Fore.RED if 'N/A' in info['Probe SSID'] else Fore.YELLOW
        mac_color = Fore.LIGHTBLUE_EX
        return [
            mac_color + mac_display + Fore.RESET,
            Fore.WHITE + ' ' + str(info.get('Signal', 'N/A')) + Fore.RESET,
            probe_color + probe_ssids + Fore.RESET,
            vendor_color + vendor_display + Fore.RESET
        ]
    else:
        return [
            mac_display,
            str(info.get('Signal', 'N/A')),
            probe_ssids,
            '-' if vendor_display == 'Unknown' else vendor_display
        ]

def format_other_device_row(mac, info, color=True):
    """Format rows for other devices, ensuring color codes are only included when color is True."""


    vendor_display = info.get('Vendor', '-')
    mac_display = f"{mac}{(Fore.YELLOW + ' *' if info.get('Randomized', False) else '')}"

    if color:
        vendor_color = Fore.LIGHTMAGENTA_EX if vendor_display == 'Unknown' else Fore.WHITE if vendor_display == '-' else Fore.LIGHTMAGENTA_EX
        mac_color = Fore.LIGHTBLUE_EX
        return [
            mac_color + mac_display + Fore.RESET,
            Fore.WHITE + ' ' + str(info.get('Signal', 'N/A')) + Fore.RESET,
            vendor_color + vendor_display + Fore.RESET
        ]
    else:
        return [
            mac_display,
            str(info.get('Signal', 'N/A')),
            '-' if vendor_display == 'Unknown' else vendor_display
        ]

def get_encryption_color(encryption):
    """Get the color for encryption types."""
    colors = {
        "Open": Fore.LIGHTGREEN_EX,
        "WPA3": Fore.RED,
        "WPA2": Fore.YELLOW,
        "WPA": Fore.LIGHTYELLOW_EX,
        "WEP": Fore.MAGENTA
    }
    return colors.get(encryption, Fore.WHITE)

def print_table(data_dict, headers, row_formatter, file=None, color=True):
    """Function to print a formatted table with consistent column widths."""
    print("\n", file=file)

    col_widths = [len(header) for header in headers]
    for key, info in data_dict.items():
        row = row_formatter(key, info, color=color)
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(strip_color_codes(cell)))

    header_line = " | ".join(f"{header:<{col_widths[i]}}" for i, header in enumerate(headers))
    print((Fore.LIGHTWHITE_EX + header_line + Fore.RESET) if color else header_line, file=file)
    print((Fore.LIGHTWHITE_EX + "-" * (sum(col_widths) + len(headers) * 3 - 1) + Fore.RESET) if color else "-" * (sum(col_widths) + len(headers) * 3 - 1), file=file)

    for key, info in data_dict.items():
        row = row_formatter(key, info, color=color)
        formatted_cells = [f"{cell}{' ' * (col_widths[i] - len(strip_color_codes(cell)))}" for i, cell in enumerate(row)]
        print(" | ".join(formatted_cells), file=file)

def strip_color_codes(text):
    """Strip ANSI color codes from a string."""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def get_mac_vendor(mac_address):
    """Function to look up the vendor of a MAC address using mac-vendor-lookup module."""
    try:
        mac_lookup = MacLookup()
        vendor = mac_lookup.lookup(mac_address)
        return vendor if vendor else '-'
    except KeyError:
        return "-"
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return "-"

def mac_lookup_worker():
    """Thread worker to process MAC lookup requests concurrently."""
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        while True:
            mac = mac_lookup_queue.get()
            
            if mac in networks and networks[mac]['Vendor'] not in ['-', 'Unknown']:
                mac_lookup_queue.task_done()
                continue
            elif mac in devices_with_ap and devices_with_ap[mac]['Vendor'] not in ['-', 'Unknown']:
                mac_lookup_queue.task_done()
                continue
            elif mac in devices_without_ap and devices_without_ap[mac]['Vendor'] not in ['-', 'Unknown']:
                mac_lookup_queue.task_done()
                continue
            elif mac in other_devices and other_devices[mac]['Vendor'] not in ['-', 'Unknown']:
                mac_lookup_queue.task_done()
                continue

            future = executor.submit(get_mac_vendor, mac)
            futures[future] = mac

            for future in as_completed(futures):
                mac = futures[future]
                try:
                    vendor = future.result()
                    update_vendor_in_tables(mac, vendor)
                except Exception as e:
                    logging.error(f"Error processing MAC {mac}: {e}")
                finally:
                    mac_lookup_queue.task_done()
                del futures[future]

def update_vendor_in_tables(mac, vendor):
    """Update the vendor information in the relevant data tables."""
    for table in [networks, devices_with_ap, devices_without_ap, other_devices]:
        if mac in table:
            table[mac]['Vendor'] = vendor

def start_sniffing(interface):
    """Function to start sniffing and handle network errors."""
    while True:
        try:
            sniff(iface=interface, prn=packet_handler)
        except KeyboardInterrupt:
            logging.info("User interrupted the script.")
            break
        except OSError as e:
            if "Network is down" in str(e):
                time.sleep(1)
                continue
            logging.error(f"An OS error occurred: {e}")
            break
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            break

def clear():

    # for windows
    if name == 'nt':
        _ = system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wi-Fi Sniffer")
    parser.add_argument("interface", help="The network interface to use, e.g., wlan0")
    parser.add_argument("-s", "--sleep", type=float, default=2, help="Sleep duration between channel hops, default is 2 seconds")
    parser.add_argument("-c", "--channel", type=int, help="Specific channel to listen on")
    parser.add_argument("-m", "--mac", help="Specific MAC address to listen for")

    args = parser.parse_args()

    interface = sanitize_interface(args.interface)
    
    if args.mac:
        if args.channel:
            while True:
                clear()
                print(f"Scanning for {args.mac} on channel {args.channel}...")
                set_channel(interface, args.channel)
                sniff(iface=interface, prn=packet_handler, store=0, timeout=0.2)
        else:
            clear()
            found_channel = find_channel_for_mac(interface, args.mac)
            if found_channel:
                set_channel(interface, found_channel)
    elif args.channel:
        set_channel(interface, args.channel)
    else:
        logging.info(f"Listening for packets on {interface} with a channel hopping sleep of {args.sleep} seconds...")
        threading.Thread(target=change_channel, args=(interface, args.sleep), daemon=True).start()

    threading.Thread(target=process_packets, daemon=True).start()
    threading.Thread(target=mac_lookup_worker, daemon=True).start()

    start_sniffing(interface)
