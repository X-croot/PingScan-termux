# PingScan v1.0 — Fast and Reliable Network Scanner

PingScan v1.0 is a powerful network scanning tool designed to quickly and efficiently discover active devices on your local network. It performs high-performance scanning over wide IP ranges by pinging each IP address to check its availability. It then retrieves the MAC addresses and estimates the operating systems of detected devices. Additionally, PingScan identifies device manufacturers by matching MAC address prefixes against a vendor database (`oui.txt`), making it easier to classify devices by brand.


## Root-Free Operation
  PingScan utilizes the system's native `ping` command directly for network scanning. This means it does not require any root access.

## Key Features

- **Fast Scanning:** Utilizes multithreading to scan hundreds of IP addresses concurrently, significantly speeding up the scanning process.
- **MAC Address & Vendor Lookup:** Retrieves MAC addresses of reachable devices and determines their manufacturers using the `oui.txt` vendor list.
- **Operating System Detection:** Estimates the OS type (Windows, Linux/macOS/Android, etc.) based on ping TTL values.

## Who Should Use PingScan?

- **System Administrators:** Gain insights into connected devices’ OS and vendor information to assist with security and inventory management.
- **Developers & Pentesters:** Ideal for anyone learning network programming, security, or system administration looking for a practical scanning tool.
<img width="904" height="426" alt="resim" src="https://github.com/user-attachments/assets/a87e7c99-382d-4911-8eaa-feac2e6f0e7c" />


## How It Works

The tool pings all IP addresses in the specified range. For each responsive device, it fetches the MAC address and looks up the manufacturer using the first six characters of the MAC address from a vendor database (`oui.txt`). It also analyzes TTL values from ping responses to provide an OS guess. Results are displayed on the console and can optionally be saved to a file.

---

## Compilation and Usage

You can compile the tool using the following command:

```bash
git clone https://github.com/X-croot/PingScan-termux.git
cd PingScan-termux
gcc pingscan.c -o pingscan -lpthread
./pingscan <start_ip> <end_ip> -o output.txt

