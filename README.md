# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Terri-Lea-P/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md
## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file that had the string "tor" in it and discovered what looks like the user "test-v1" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "tor-shopping-list.txt" on the desktop at 2026-01-21T13:51:25.9295279Z. These events began at : (2026-01-21T12:39:06.4671489Z)

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "tp--tp--tp"
| where InitiatingProcessAccountName == "test-v1"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-01-21T12:39:06.4671489Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="3476" height="934" alt="image" src="https://github.com/user-attachments/assets/3da1fc45-836a-46c5-9792-555b2c33948f" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.4.exe"

Based on the logs returned, at 2026-01-21T13:40:16.8335796Z, the user "test-v1" on device "tp--tp--tp" quietly launched a portable Tor Browser executable from their Downloads folder, running it without installation in a way that would allow anonymous internet access with minimal visible traces on the system, using a command that triggered a silent installation. 

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "tp--tp--tp"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.4.exe"
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="3626" height="453" alt="image" src="https://github.com/user-attachments/assets/bfa2cb5e-d2f7-47fe-bf09-47dca39dcbeb" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user "employee" actually opened the tor browser. There was evidence that they did open it at: 2026-01-21T13:40:27.6742578Z
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "tp--tp--tp"
| where FileName has_any ("tor-browser.exe", "firefox.exe", "tor.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="3043" height="1417" alt="image" src="https://github.com/user-attachments/assets/fae7629d-ca2f-46f2-9d5c-3ba9d903257a" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. 

At 2026-01-21T12:41:55.3831152Z, the user "test-v1" on device "tp--tp--tp" successfully made an outbound network connection from the Tor executable located at "C:\Users\test-v1\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe" to the external IP address "37.114.53.9" over port "9001", showing the Tor client was actively communicating with a Tor relay node on the internet. There were a few other connections.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "tp--tp--tp"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9050", "9150", "9051", "9001", "9030", "9052")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="3747" height="423" alt="image" src="https://github.com/user-attachments/assets/849f2894-ab45-4543-9b5b-3dc07c430469" />


---

## Chronological Event Timeline 

### 1. 12:38:41 – The file `tor-browser-windows-x86_64-portable-15.0.4.exe` is executed from the Downloads folder, indicating the Tor Browser portable package was launched for the first time.

### 2.  12:39:06 – 12:41:27 – A large number of **Tor-related files** are created on the Desktop under a new _Tor Browser_ folder structure.
    
    - Includes `tor.exe`, Tor configuration files, launcher components, and browser support files.
        
    - A desktop shortcut **“Tor Browser.lnk”** is also created, confirming setup completion.

### 3. 12:41:17 – 12:41:27 – Multiple Tor Browser processes start:
    
    - `tor.exe` launches (Tor network service)
        
    - `firefox.exe` launches (Tor Browser UI)
        
    - Several sandboxed `firefox.exe -contentproc` child processes appear (browser tabs)

### 4. 12:41:55 – The Tor process at  
    C:\Users\Test-V1\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe 
    makes a successful outbound connection to **37.114.53.9 over port 9001**, which is consistent with communication to a Tor relay node.

### 5. 12:48:44 – The original Tor installer executable is **deleted** from the Downloads folder, removing the initial artifact.
    

### 6. 13:39:22 – 13:40:16 – The Tor installer executable is run again from Downloads, suggesting a second launch or re-execution of the portable package.

### 7. 13:40:27 onward – Tor Browser processes (`firefox.exe`, `tor.exe`, and multiple content processes) appear again, confirming the browser was reopened and actively used.

### 8. 13:51:25 – A file named `tor-shopping-list.txt` is created in the user’s Documents folder, followed shortly by a shortcut (`.lnk`) reference. This indicates user activity occurring during the Tor session.



---

## Summary

User test-v1 downloaded and ran the portable Tor Browser, which unpacked and executed directly from the Desktop. The Tor service started, Tor Browser opened with multiple active tabs, and the system established live connections to the Tor network via relay port 9001. The original installer was later deleted, reducing obvious installation traces. The browser was launched again later the same day, during which a document titled “tor-shopping-list.txt” was created, showing active user interaction while Tor was in use.

## Conclusion: 

Confirmed intentional installation and active use of Tor Browser for anonymized internet access on this device.

---

## Response Taken

TOR usage was confirmed on the endpoint `tp--tp--tp` by the user `test-v1`. The device was isolated, and the user's direct manager was notified.

---
