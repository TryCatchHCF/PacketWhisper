# PacketWhisper
PacketWhisper - Stealthily Transfer Data & Defeat Attribution Using DNS Queries & Text-Based Steganography, without the need for attacker-controlled Name Servers or domains; Evade DLP/MLS Devices; Defeat Data- & DNS Name Server Whitelisting Controls. Convert any file type (e.g. executables, Office, Zip, images) into a list of Fully Qualified Domain Names (FQDNs), use DNS queries to transfer data. Simple yet extremely effective.

# Author
Joe Gervais (TryCatchHCF)

# Why is this different from every other DNS exfiltration technique?
Traditional DNS exfiltration relies on one of the following: DNS tunneling; Hiding data in DNS query fields; or Encoded / encrypted payloads that are broken up and used as subdomains in the DNS query. All of these methods require that the attacker control a domain and/or an associated DNS Name Server to receive the data, which leads to attribution. Those approaches are also vulnerable to DNS Name Server blacklisting (common) and whitelisting (increasingly common). Another problem is that DFIR analysts are familiar with these methods, and SIEM systems will often detect and alert on seeing them.

PacketWhisper overcomes these limitations. 

What if data could be transferred using the target's own whitelisted DNS servers, without the communicating systems ever directly connecting to each other or to a common endpoint? Even if the network boundary employed data whitelisting to block data exfiltration?

# How It Works
To make it all happen, PacketWhisper combines DNS queries with text-based steganography. Leveraging the <a href="https://github.com/TryCatchHCF/Cloakify">Cloakify Toolset</a>, it transforms the payload into a list of FQDN strings. PacketWhisper then uses the list of FQDNs to create sequential DNS queries, transferring the payload across (or within) network boundaries, with the data hidden in plain sight, and without the two systems ever directly connecting to a each other or to a common endpoint. The ciphers used by PacketWhisper provide multiple levels of deception to avoid generating alerts as well as to mislead analysis attempts.

To receive the data, you capture the network traffic containing the DNS queries, using whatever method is most convenient for you. (See "Capturing The PCAP File" below for examples of capture points.) You then load the captured PCAP file into PacketWhisper (running on whatever system is convenient), which extracts the payload from the file and Decloakifies it into its original form.

DNS is an attractive protocol to use because, even though it's a relatively slow means of transferring data, DNS is almost always allowed across network boundaries, even on the most sensitive networks.

<b>Important note:</b> We're using DNS queries to transfer the data, not successful DNS lookups. PacketWhisper never needs to successfully resolve any of its DNS queries. In fact PacketWhisper doesn't even look at the DNS responses. This expands our use cases, and underscores the fact that we never need to control a domain we're querying for, never need to control a DNS Name Server handling DNS requests.

So using PacketWhisper, we transform a payload that looks like this:

<img src=https://github.com/TryCatchHCF/PacketWhisper/blob/master/screenshots/payloadAcctSpreadsheet.png></img>

Into a list of FQDNs like this:

<img src=https://github.com/TryCatchHCF/PacketWhisper/blob/master/screenshots/PacketWhisperWorkflow.png></img>

Which PacketWhisper turns into DNS queries that show up in network traffic like this:

<img src=https://github.com/TryCatchHCF/PacketWhisper/blob/master/screenshots/PacketWhisperNetworkTraffic.png></img>

Which you capture as a PCAP file anywhere along the DNS resolution path, and then load that PCAP into your local copy of PacketWhisper to recover the payload:

<img src=https://github.com/TryCatchHCF/PacketWhisper/blob/master/screenshots/PacketWhisperExtractPayload.png></img>

# Tutorial
See the DEF CON 26 slides (included in project) from my Packet Hacking Village presentation. The slides present background on DNS exfiltration, text-based steganography / Cloakify Toolset, and how PacketWhisper combines them all into a method for transferring data. I specifically created the slides to be useful on their own, so the background and information should be complete. However you can also <a href="https://www.youtube.com/watch?v=9CoZUulhiwo">view the video of my DC26 Packet Hacking Village presentation</a> which provides additional context.

I've included a sample PCAP file in the project (cleverly named "sample.pcap") that contains separate payloads for each of the ciphers. They could have been any filetype, of course, but in this case I just transmitted text files into the PCAP. Load it up in PacketWhisper and give it a try!

As a quick test in your own environment, run PacketWhisper from a VM, then send a file while doing a packet capture on the VM's network interface via the host system. You can then load the PCAP file into whichever PacketWhisper instance is convenient to decode the file. Just remember it's not a speedy transfer. Smaller files and patience are your friend.

# Requires
1) Python 2.7.x (3.6.x port is underway)<br>
2) For decoding payloads: tcpdump (included on Linux & MacOS) or <a href="https://www.winpcap.org">WinDump</a> (Windows)

<b>Question:</b> "Why didn't you use Scapy or dnspython toolset?"

<b>Answer:</b> I hate project dependencies in my operational tools. I keep my projects as atomic, self-contained as possible for maximum reliability, especially on the client side where I may not control the environment and/or have minimal privileges. The way PacketWhisper is structured, I can get it running on a limited shell host just by tar'ing up the project and extracting on the target host.

<b>Question:</b> "Why isn't PacketWhisper a project fork of Cloakify Toolset?"

<b>Answer:</b> Same answer as above. We only need a very specific subset of Cloakify's capabilities, and adding everything else to PacketWhisper would just lead to a cluttered directory and tools/ciphers that can't be used by PacketWhisper. Since I own both projects, I promise to synchronize any changes between the two.

# Run PacketWhisper
$ python packetWhisper.py

# FQDN-Based Ciphers
FQDN-based ciphers consist of 3 categories:

1) Unique Random Subdomain FQDNs  (Recommended - avoids DNS caching, overcomes NAT) <br>
2) Unique Repeating FQDNs  (DNS may cache, but overcomes NAT) <br>
3) Common Website FQDNs    (DNS caching may block, NAT interferes) <br>

<b>Unique Random Subdomain FQDNs</b>

RECOMMENDED CIPHER MODE FOR MOST USE CASES
	
These are FQDNs with randomized elements built into the subdomains. This helps prevent DNS caching, while also allowing us to transfer data beyond a NAT'd network devices that may be along the DNS query path. Since the sending system's IP address isn't available beyond the NAT device, the cipher-generated subdomains contain unique tag elements to help us identify PacketWhisper payloads in the packet capture. 

These ciphers mimic the formats of various services that rely on complex subdomains as a means to identify a session, user, cached content etc. This approach helps PacketWhisper's DNS queries blend in with the rest of the network's traffic.

The first part of the subdomain name is actually a string from the cipher list. The rest of the subdomain name is randomized to make each FQDN unique, which prevents DNS caching from shutting down the DNS query path prematurely. We then add the domain name. We construct the FQDNs this way to look like the usual FQDNs associated with the selected domain, to blend in better with normal webtraffic seen on any network.
	
<img src=https://github.com/TryCatchHCF/PacketWhisper/blob/master/screenshots/FQDN_cipher1.png></img>

<b>Unique Repeating FQDNs</b>

Created to stand out from all other DNS queries on the network, but without any randomization involved. This means that DNS caching may interfere, but as a side benefit your DNS queries will be easy for you to find even in the largest collection of multi-client pcaps. This is due to the fact that the FQDNs are odd endpoints, like the list of "Johns" (Red Lectroid aliens) at the fictional Yoyodyne Propulsion Systems from the movie 'Buckaroo Banzai Across the 8th Dimension'.

<img src=https://github.com/TryCatchHCF/PacketWhisper/blob/master/screenshots/FQDN_cipher2.png></img>

<b>Common Website FQDNs</b>

These are FQDNs constructed out of common Website URLs.

NOTE: Since most environments are NAT'd at the perimeter (removing visibility of client's IP address), this mode is generally only useful for transferring data between systems connected to the same local /24 network (for example, the guest wifi at your favorite coffee shop).

Since Common Website ciphers only have the source IP address as a way to distinguish its queries from all the other similar DNS queries on the network, PacketWhisper will transmit a unique "knock sequence" DNS query at beginning and end of the payload, which helps us pick out the transmitting host from the pcap file later.

Example FQDN:  www.github.com


# Transmitting the Cloakified Payload
Once you've selected a cipher, PacketWhisper encodes (Cloakifies) the payload into a list of FQDN strings per the desired cipher. It then sequentially generates DNS requests to send the data along the DNS resolution path. PacketWhisper adds a small delay between each DNS query, which helps prevent out-of-order DNS requests.

# Capturing the PCAP File
The key element here is of course being able to capture the network traffic containing the DNS queries that PacketWhisper generated. There are a lot of options, since you only need to be somewhere, anywhere, with visibility to the DNS query path.

Example Points of Capture:<br>

- Connected to the same local network (e.g. your local coffee shop)<br>
- Systems and devices that are internal to the organization<br>
- Perimeter network appliances<br>
- Network infrastructure outside of the organization<br>
- Network tap anywhere along the query path<br>

Use your imagination. Any device along the DNS resolution path is an option, including wall displays. "Wait, what?"

<img src=https://github.com/TryCatchHCF/PacketWhisper/blob/master/screenshots/PacketWhisperWallDisplayCapture.png></img>

<b>NOTE: VPN connections block visibility between host and VPN exit node.</b> If the client you're transferring from has an active VPN connection, you won't be able to see any DNS queries unless you can capture upstream from the VPN exit node. Even capturing on the same system will fail. Since many of you are probably using VPNs, if you want to test out PacketWhisper, try transmitting from a hosted virtual machine (VM) and capture the traffic on the VM's network interface on the host system.

# Extracting The Payload
Once you've captured the pcap file, recover the payload by running PacketWhisper on a system that has tcpdump (included on Linux & MacOS) or <a href="https://www.winpcap.org">WinDump</a> (Windows) installed. PacketWhisper will ask you which cipher was used, then extract the payload from the pcap, and finally decode the extracted payload with the matching cipher.

<b>Important note:</b> Within the same PCAP, you can transmit one payload per cipher used. A PCAP containing more than one payload using the same cipher will cause problems. For example my supplied 'example.pcap' file contains 5 payloads, one for each of the operational ciphers currently available. If one of the payloads had used the same cipher as another one, PacketWhisper will fail to extract either of them. The easy fix is to break up the PCAP file (this is why the PacketWhisper transmit code prints out the UTC date-time when starting and ending transmission). I'm working on allowing multiple payloads using the same cipher, solution is already in place, I just need to get around to it. 

# Limitations / Use Notes

<b>Be sure your PCAP file is actually PCAP format.</b> If you used tcpdump or WinDump to capture the file you'll be fine. Wireshark however offers a wide variety of "Save As..." options for saving Wireshark traffic, only one of which is actually tcpdump/PCAP friendly. I'm working on better error reporting to help catch mistakes early.

<b>Not a secure encryption scheme.</b> PacketWhisper is not a secure encryption scheme. It's vulnerable to frequency analysis attacks. Use the 'Unique Random Subdomain FQDNs' category of ciphers to add entropy and help degrade frequency analysis attacks. If payload secrecy is required, be sure to encrypt the payload before using PacketWhisper to process it.

<b>Not a high-bandwidth transfer method.</b> PacketWhisper relies on DNS queries, which are UDP-based, meaning order of delivery (or even successful delivery) of the request is not guaranteed. PacketWhisper by default adds a small (1/2-second) delay between each DNS query. You can safely transfer payloads at a rate of about 7.2K per hour (120 bytes per minute). That's based on the size of the original payload, not the Cloakified output file. You can opt for no delay between between queries, which dramatically speeds up the transfer but at the risk of increased network noise and corrupted payload.

And let's face it, if you have non-DNS modes of data transfer available, you can just use the main <a href="https://github.com/TryCatchHCF/Cloakify">Cloakify Toolset</a> project to hide the file in plain sight (maybe turn the payload into a list of PokemonGo monsters w/ LatLon coordinates) and use all that high bandwidth available via FTP/HTTP/etc. DNS is extremely useful when other protocols are blocked, but always be aware of your options.

<b>DNS is DNS.</b> Different OS's have different DNS caching policies, etc. Networks may be down, isolated, etc. PacketWhisper includes a quick manual check to see if it can resolve common FQDNs, but DNS is often a messy business. Remember the old IT troubleshooting mantra: "It's always DNS."


# Detection / Prevention
See the DEF CON 26 slides (included in project) from my Packet Hacking Village presentation. Mitigation strategies are covered toward the end of the presentation. As in all things, "Security In Depth" is your friend, especially since DNS resolution paths span vast amounts of terrain that are outside of your organization's control.


# Roadmap
I'll be adding modes for MDNS and LLMNR local network DNS broadcast modes. These are intended to be used by systems connected to the same local network, and will remove the need for the capturing device to have access to Promiscuous Mode when performing wifi packet captures. (Those protocols send traffic to x.y.z.255 on the host network, broadcasting traffic to all other systems on the same local network.)

I'll also add more ciphers, but for day-to-day needs the current cipher collection is all I've ever needed. You'll get good mileage out of them.

I'm also working on allowing multiple payloads using the same cipher in a single PCAP file. Solution is already prototyped, but it makes the PCAP extraction workflow uglier for the user. Operationally it might be more trouble that it's worth. I always prefer cleaner ops functionality than Swiss army knife complexity.
