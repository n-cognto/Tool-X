import subprocess

# Function to list all available Wi-Fi networks
def list_wifi_networks():
    try:
        # Use nmcli to list Wi-Fi networks
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SECURITY", "dev", "wifi"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise Exception("Failed to list Wi-Fi networks")

        networks = result.stdout.split("\n")
        wifi_list = []

        # Extract network information
        for network in networks:
            if not network:
                continue
            ssid, security = network.split(":")
            wifi_list.append({"SSID": ssid, "Security": security})

        return wifi_list

    except Exception as e:
        print("Error listing Wi-Fi networks:", e)
        return []

# Function to get the clear key (Wi-Fi password) for a given network
def get_wifi_password(ssid):
    try:
        # Get the connection details for the specified SSID
        result = subprocess.run(
            ["nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", ssid],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise Exception("Failed to retrieve Wi-Fi password")

        # Extract the clear key from the output
        password = result.stdout.strip()
        return password

    except Exception as e:
        print("Error getting Wi-Fi password:", e)
        return None

# Get a list of available Wi-Fi networks
wifi_networks = list_wifi_networks()

if wifi_networks:
    print("Available Wi-Fi Networks:")
    for wifi in wifi_networks:
        ssid = wifi["SSID"]
        print(f"SSID: {ssid}")
        print(f"Security: {wifi['Security']}")

        # Get the Wi-Fi password for the SSID
        wifi_password = get_wifi_password(ssid)

        if wifi_password:
            print(f"Password for {ssid}: {wifi_password}")
        else:
            print(f"Could not retrieve password for {ssid}.")
        print()

else:
    print("No Wi-Fi networks found.")
