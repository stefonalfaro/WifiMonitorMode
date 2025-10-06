# Wifi Monitor Mode Access Point and Device Scanner

Many people don't realize but all wifi traffic is public. You can associate user devices to the access point they are connected to without being connected to the network itself.

<img width="602" height="859" alt="Screenshot from 2025-10-06 11-34-15" src="https://github.com/user-attachments/assets/f4fcb9ae-bcae-4781-bb8b-a052c8ced0e6" />

## Monitor Mode

This cannot be done on Windows as the operating system is too restrictive so you need to use a kernel that allows this. Monitor mode is supported by most WiFi cards and is a normal feature that is built in. You need to set your interface into Monitor mode and then even using Wireshark you can see all the raw air traffic.

### Airmon-ng

This is most commonly done with airmon-ng
```
# First, check for interfering processes
sudo airmon-ng check

# Kill interfering processes (NetworkManager, wpa_supplicant, etc.)
sudo airmon-ng check kill

# Start monitor mode on wlo1
sudo airmon-ng start wlo1
```

And provides the best managed way to do this as it will create a new interface specifically for this. In my case the wlo1 regular interface becomes a new wlo1mon that we would use.
```
# Check what interfaces exist now
iwconfig

# or
ip link show
```

## Why C#

C# is great as it can do almost everything low level languages can do at around 95% of the preformance. You don't need to be writing native code to handle these types of projects.
