import os
import time
import sys
from scapy.all import *
from collections import defaultdict
import threading
from colorama import Fore, Style, init
import logging
import argparse
import re
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from mac_vendor_lookup import MacLookup  # Import mac-vendor-lookup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize colorama
init(autoreset=True)

# Dictionary to store access points, devices, and associations
networks = defaultdict(dict)
devices_with_ap = defaultdict(dict)
devices_without_ap = defaultdict(dict)
other_devices = defaultdict(dict)
associations = defaultdict(set)

packet_queue = Queue()
mac_lookup_queue = Queue()

def sanitize_interface(interface):
    """Sanitize the network interface input to prevent injection attacks."""
    if re.match(r'^[a-zA-Z0-9_-]+$', interface):
        return interface
    else:
        logging.error(f"Invalid interface name provided: {interface}")
        sys.exit(1)

def change_channel(interface, sleep_duration):
    """Function to change the Wi-Fi channel periodically for channel hopping."""
    ch = 1
    while True:
        try:
            os.system(f"iwconfig {interface} channel {ch}")
            ch = ch % 13 + 1  # Channels 1-14 (2.4 GHz)
            time.sleep(sleep_duration)  # Hop every sleep_duration seconds
        except Exception as e:
            logging.error(f"An error occurred while changing channel: {e}")

def packet_handler(packet):
    """Function to handle each captured packet."""
    try:
        packet_queue.put(packet)
    except Exception as e:
        logging.error(f"An error occurred while putting packet to queue: {e}")

def process_packets():
    """Function to process packets from the queue."""
    while True:
        packet = packet_queue.get()
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
            print_network_data()

        except AttributeError:
            pass
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            packet_queue.task_done()

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
    
    is_randomized = check_randomized_mac(bssid)
    
    # Add to networks table and remove from other tables if necessary
    if bssid not in networks:
        networks[bssid] = {'SSID': ssid, 'Signal': dbm_signal, 'Channel': channel, 'Encryption': encryption, 'Vendor': '-', 'Randomized': is_randomized}
        mac_lookup_queue.put(bssid)  # Add BSSID for lookup
    else:
        networks[bssid].update({'SSID': ssid, 'Signal': dbm_signal, 'Channel': channel, 'Encryption': encryption})
    
    # Ensure BSSID does not appear in any other table
    if bssid in devices_with_ap:
        del devices_with_ap[bssid]
    if bssid in devices_without_ap:
        del devices_without_ap[bssid]
    if bssid in other_devices:
        del other_devices[bssid]

def process_probe_request(packet):
    mac = packet.addr2
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'
    probe_ssid = packet.info.decode('utf-8', errors='ignore') if packet.info else 'N/A'
    
    is_randomized = check_randomized_mac(mac)
    
    if mac not in networks and mac not in devices_with_ap:
        if mac not in devices_without_ap and mac not in other_devices:
            # Check if Probe SSID is 'N/A'
            if probe_ssid == 'N/A':
                # If Probe SSID is 'N/A', add to other_devices
                other_devices[mac] = {'Signal': dbm_signal, 'Vendor': '-', 'Randomized': is_randomized}
            else:
                # If Probe SSID is not 'N/A', add to devices_without_ap
                devices_without_ap[mac] = {'Signal': dbm_signal, 'Probe SSID': probe_ssid, 'Vendor': '-', 'Randomized': is_randomized}
            mac_lookup_queue.put(mac)  # Add MAC for lookup
        else:
            if mac in devices_without_ap:
                devices_without_ap[mac].update({'Signal': dbm_signal, 'Probe SSID': probe_ssid})
            elif mac in other_devices:
                other_devices[mac].update({'Signal': dbm_signal})

def process_data_frame(packet):
    bssid = packet.addr1  # BSSID of the AP
    client_mac = packet.addr2  # MAC address of the client device
    dbm_signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'

    is_randomized = check_randomized_mac(client_mac)

    if bssid in networks:
        associations[bssid].add(client_mac)

        # Only add to devices_with_ap if it has a valid associated AP (bssid)
        if bssid and client_mac not in networks and client_mac not in devices_with_ap:
            devices_with_ap[client_mac] = {'Signal': dbm_signal, 'Associated AP': bssid, 'Vendor': '-', 'Randomized': is_randomized}
            mac_lookup_queue.put(client_mac)  # Add client MAC for lookup if not already in queue

        # Ensure client_mac is not in devices_without_ap or other_devices
        if client_mac in devices_without_ap:
            del devices_without_ap[client_mac]
        if client_mac in other_devices:
            del other_devices[client_mac]
    
    else:
        # If the BSSID is not recognized as a network, treat the device as an "other" device
        if client_mac not in networks and client_mac not in devices_with_ap:
            if client_mac not in other_devices:
                other_devices[client_mac] = {'Signal': dbm_signal, 'Vendor': '-', 'Randomized': is_randomized}
                mac_lookup_queue.put(client_mac)  # Add client MAC for lookup if not already in queue

        # Ensure the client_mac is not in devices_without_ap
        if client_mac in devices_without_ap:
            del devices_without_ap[client_mac]

def check_randomized_mac(mac):
    """Check if the MAC address is randomized."""
    return mac[1].upper() in ['A', 'E', '2', '6']

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

def print_network_data():
    """Function to

 print all network data in a formatted way."""
    os.system('clear')
    print_table(networks, ['BSSID', 'SSID', 'Signal', 'Channel', 'Encryption', 'Vendor'], format_network_row)
    print_table(devices_with_ap, ['MAC', 'Signal', 'Associated AP', 'Vendor'], format_associated_device_row)
    print_table(devices_without_ap, ['MAC', 'Signal', 'Probe SSID', 'Vendor'], format_non_associated_device_row)
    print_table(other_devices, ['MAC', 'Signal', 'Vendor'], format_other_device_row)

def format_network_row(bssid, info):
    vendor_display = info['Vendor']
    # Determine vendor color: magenta for found or 'Unknown', white for initial '-'
    vendor_color = Fore.LIGHTMAGENTA_EX if info['Vendor'] == 'Unknown' else Fore.WHITE if info['Vendor'] == '-' else Fore.LIGHTMAGENTA_EX
    mac_display = bssid + Fore.YELLOW + ' *' + Fore.RESET if info.get('Randomized', False) else bssid
    return [
        Fore.LIGHTBLUE_EX + mac_display + Fore.RESET,
        Fore.LIGHTGREEN_EX + info['SSID'] + Fore.RESET,
        Fore.WHITE + ' ' + str(info['Signal']) + Fore.RESET,  # Added space before Signal
        Fore.WHITE + '   ' + str(info['Channel']) + Fore.RESET,  # Added three spaces before Channel
        get_encryption_color(info['Encryption']) + '   ' + info['Encryption'] + Fore.RESET,  # Added three spaces before Encryption
        vendor_color + ('-' if info['Vendor'] == 'Unknown' else vendor_display) + Fore.RESET
    ]

def format_associated_device_row(mac, info):
    """Format rows for associated devices."""
    vendor_display = info['Vendor']
    vendor_color = Fore.LIGHTMAGENTA_EX if info['Vendor'] == 'Unknown' else Fore.WHITE if info['Vendor'] == '-' else Fore.LIGHTMAGENTA_EX
    mac_display = mac + Fore.YELLOW + ' *' + Fore.RESET if info.get('Randomized', False) else mac
    associated_ap_display = networks[info['Associated AP']]['SSID'] if info['Associated AP'] in networks else 'N/A'
    return [
        Fore.LIGHTBLUE_EX + mac_display + Fore.RESET,
        Fore.WHITE + ' ' + str(info['Signal']) + Fore.RESET,  # Added space before Signal
        Fore.LIGHTGREEN_EX + associated_ap_display + Fore.RESET,
        vendor_color + ('-' if info['Vendor'] == 'Unknown' else vendor_display) + Fore.RESET
    ]

def format_non_associated_device_row(mac, info):
    probe_color = Fore.RED if info['Probe SSID'] == 'N/A' else Fore.YELLOW
    vendor_display = info['Vendor']
    vendor_color = Fore.LIGHTMAGENTA_EX if info['Vendor'] == 'Unknown' else Fore.WHITE if info['Vendor'] == '-' else Fore.LIGHTMAGENTA_EX
    mac_display = mac + Fore.YELLOW + ' *' + Fore.RESET if info.get('Randomized', False) else mac
    return [
        Fore.LIGHTBLUE_EX + mac_display + Fore.RESET,
        Fore.WHITE + ' ' + str(info['Signal']) + Fore.RESET,
        probe_color + info['Probe SSID'] + Fore.RESET,
        vendor_color + ('-' if info['Vendor'] == 'Unknown' else vendor_display) + Fore.RESET
    ]

def format_other_device_row(mac, info):
    vendor_display = info['Vendor']
    vendor_color = Fore.LIGHTMAGENTA_EX if info['Vendor'] == 'Unknown' else Fore.WHITE if info['Vendor'] == '-' else Fore.LIGHTMAGENTA_EX
    mac_display = mac + Fore.YELLOW + ' *' + Fore.RESET if info.get('Randomized', False) else mac
    return [
        Fore.LIGHTBLUE_EX + mac_display + Fore.RESET,
        Fore.WHITE + ' ' + str(info['Signal']) + Fore.RESET,  # Added space before Signal
        vendor_color + ('-' if info['Vendor'] == 'Unknown' else vendor_display) + Fore.RESET
    ]

def get_encryption_color(encryption):
    if encryption == "Open":
        return Fore.LIGHTGREEN_EX
    elif encryption == "WPA3":
        return Fore.RED
    elif encryption == "WPA2":
        return Fore.YELLOW
    elif encryption == "WPA":
        return Fore.LIGHTYELLOW_EX
    else:
        return Fore.WHITE

def print_table(data_dict, headers, row_formatter):
    """Function to print a formatted table with consistent column widths."""
    print("\n")

    # Calculate column widths using the maximum length of headers and unformatted data
    col_widths = [len(header) for header in headers]
    
    # Adjust column widths based on the longest content in each column, excluding color codes
    for key, info in data_dict.items():
        row = row_formatter(key, info)
        for i, cell in enumerate(row):
            content_length = len(strip_color_codes(cell))
            col_widths[i] = max(col_widths[i], content_length)


    # Print headers with calculated widths
    header_line = " | ".join(f"{header:<{col_widths[i]}}" for i, header in enumerate(headers))
    print(Fore.LIGHTWHITE_EX + header_line + Fore.RESET)
    print(Fore.LIGHTWHITE_EX + "-" * (sum(col_widths) + len(headers) * 3 - 1) + Fore.RESET)

    # Print rows with consistent column widths
    for key, info in data_dict.items():
        row = row_formatter(key, info)

        # Calculate the formatted row to match the header alignment
        formatted_cells = []
        for i, cell in enumerate(row):
            # Strip color codes to calculate actual content length
            content_length = len(strip_color_codes(cell))
            # Calculate padding required for the actual content
            padding_needed = col_widths[i] - content_length
            # Format cell with padding to match column width
            formatted_cells.append(f"{cell}{' ' * padding_needed}")
        
        # Join the formatted cells with white '|' characters
        formatted_row = Fore.LIGHTWHITE_EX + " | ".join(formatted_cells) + Fore.RESET
        print(formatted_row)

def strip_color_codes(text):
    """Strip color codes for proper width calculation."""
    # Regex pattern to match ANSI escape sequences
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def get_mac_vendor(mac_address):
    """Function to look up the vendor of a MAC address using mac-vendor-lookup module."""
    try:
        # Initialize the MacLookup instance
        mac_lookup = MacLookup()
        
        # Optional: Update the local MAC address database (if needed)
        # mac_lookup.update_vendors()

        # Look up the vendor for the given MAC address
        vendor = mac_lookup.lookup(mac_address)
        return vendor

    except KeyError:
        return "Unknown"
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return "Unknown"

def mac_lookup_worker():

    logging.getLogger().setLevel(logging.ERROR)
    """Thread worker to process MAC lookup requests concurrently."""
    with ThreadPoolExecutor(max_workers=10) as executor:  # Use 10 threads for parallel lookups
        futures = {}
        while True:
            mac = mac_lookup_queue.get()

            # Skip lookups if we already have a known vendor
            if (mac in networks and networks[mac].get('Vendor') not in ['-', 'Unknown']) or \
               (mac in devices_with_ap and devices_with_ap[mac].get('Vendor') not in ['-', 'Unknown']) or \
               (mac in devices_without_ap and devices_without_ap[mac].get('Vendor') not in ['-', 'Unknown']) or \
               (mac in other_devices and other_devices[mac].get('Vendor') not in ['-', 'Unknown']):
                mac_lookup_queue.task_done()
                continue

            future = executor.submit(get_mac_vendor, mac)
            futures[future] = mac

            # Process completed futures
            for future in as_completed(futures):
                mac = futures[future]
                try:
                    vendor = future.result()
                    logging.info(f"Processed MAC: {mac}, Vendor: {vendor}")
                    
                    # Update the relevant dictionaries based on lookup result
                    if mac in networks:
                        networks[mac]['Vendor'] = vendor
                    elif mac in devices_with_ap:
                        devices_with_ap[mac]['Vendor'] = vendor
                    elif mac in devices_without_ap:
                        devices_without_ap[mac]['Vendor'] = vendor
                    elif mac in other_devices:
                        other_devices[mac]['Vendor'] = vendor
                except Exception as e:
                    logging.error(f"Error processing MAC {mac}: {e}")
                finally:
                    mac_lookup_queue.task_done()
                # Remove the future from the dictionary
                del futures[future]

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
                time.sleep(1)  # Wait a bit before restarting
                continue  # Restart sniffing
            else:
                logging.error(f"An OS error occurred: {e}")
                break
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wi-Fi Sniffer")
    parser.add_argument("interface", help="The network interface to use, e.g., wlan0")
    parser.add_argument("-s", "--sleep", type=float, default=2, help="Sleep duration between channel hops, default is 2 seconds")
    
    args = parser.parse_args()

    # Sanitize interface input
    interface = sanitize_interface(args.interface)
    
    logging.info(f"Listening for packets on {interface} with a channel hopping sleep of {args.sleep} seconds...")

    # Start the channel hopping in a separate thread
    channel_hop_thread = threading.Thread(target=change_channel, args=(interface, args.sleep))
    channel_hop_thread.daemon = True
    channel_hop_thread.start()

    # Start the packet processing in a separate thread
    packet_processing_thread = threading.Thread(target=process_packets)
    packet_processing_thread.daemon = True
    packet_processing_thread.start()

    # Start the MAC lookup in a separate thread with concurrent requests
    mac_lookup_thread = threading.Thread(target=mac_lookup_worker)
    mac_lookup_thread.daemon = True
    mac_lookup_thread.start()

    # Start sniffing on the specified interface
    start_sniffing(interface)
