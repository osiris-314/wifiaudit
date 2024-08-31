# WIFI Auditing
This Tool is a powerful Python application designed to monitor and analyze Wi-Fi networks. It leverages the capabilities of the Scapy library to capture and analyze 802.11 packets, facilitating insights into network behavior, security posture, and operational performance. This tool is particularly useful for network administrators, security professionals, and enthusiasts interested in wireless technologies.
##
```
python wifiaudit.py <interface_name_here>
```

![wifi_audit_image](https://github.com/user-attachments/assets/8f0073e8-7ea6-4452-80b4-aa710c825db2)

## Features

- **Channel Hopping:** Dynamically changes the Wi-Fi channel to monitor traffic across multiple frequencies.
- **MAC Address Filtering:** Allows targeting specific devices by filtering out packets based on MAC addresses.
- **Real-Time Statistics:** Displays statistics such as signal strength, data rates, and encryption type, updated in real-time.
- **Vendor Lookup:** Identifies the manufacturer of the network hardware by MAC address using the mac-vendor-lookup library.
- **Color-Coded Output:** Utilizes colorama for enhanced terminal output, making the data easier to read and understand.
- **Mac-Randomization:** Randomized MAC addresses have an asterisk(*) next to them.
  
## To scan for specific channel:
```
python wifiaudit.py <interface_name_here> -c <channel_number_here>
```
## To scan for specific MAC address:
```
python wifiaudit.py <interface_name_here> -m xx:xx:xx:xx:xx:xx
```
## To change how many seconds the interface will listent each channel:
```
python wifiaudit.py <interface_name_here> -s <channel_hopping_in_seconds>
```

## First Table ( Networks )
- All nearby networks as displayed here

## Second Table ( Associated Ap Decices )
- All devices that are connected to one of the networks we have already found

## Third Table ( No Associated Ap Devices )
- All devices that are not connected to a network but have send out probes to connect to one or more

## Forth Table ( Other Devices )
- All devices that have not associated AP and havent probed to connect to a network yet

