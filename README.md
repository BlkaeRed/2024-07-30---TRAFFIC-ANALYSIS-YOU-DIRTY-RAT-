"# 2024-07-30---TRAFFIC-ANALYSIS-YOU-DIRTY-RAT-" 

SCENARIO

LAN segment data:

  LAN segment range:  172.16.1[.]0/24 (172.16.1[.]0 through 172.16.1[.]255)
  
  Domain:  wiresharkworkshop[.]online
  
  Domain controller:  172.16.1[.]4 - WIRESHARK-WS-DC
  
  LAN segment gateway:  172.16.1[.]1
  
  LAN segment broadcast address:  172.16.1[.]255

TASK

  Write an incident report based on malicious network activity from the pcap.
  
  The incident report should contains 3 sections:
  
    Executive Summary: State in simple, direct terms what happened (when, who, what).
    
    Victim Details: Details of the victim (hostname, IP address, MAC address, Windows user account name).
    
    Indicators of Compromise (IOCs): IP addresses, domains and URLs associated with the activity.  SHA256 hashes if any malware binaries can be extracted from the pcap.
  
At first, I briefly scanned through the data to understand what I would be dealing with. I noticed a lot of TLS encrypted traffic, so I tried to find the Encryption Key Log File for this exercise. Unfortunately, there wasn't one available, meaning I wouldn't be able to decrypt this traffic.

Next, I looked for the start of any connection between a host inside the LAN and a host outside of it. While doing so, I came across several different and potentially suspicious IP addresses and domain names: 141.98.10.79, 199.232.196.209 (repo1.maven.org), and 185.199.110.133 (objects.githubusercontent.com). All of them were communicating with the IP address 172.16.1.66, leading me to suspect that this host might be the victim.

I then checked the TCP stream for all these communications. Most of them were TLS encrypted, as expected, but the stream for 141.98.10.79 was not. In this stream, I found evidence of malware infection, specifically STRRAT malware. This confirmed that the host at 172.16.1.66 was infected and that 141.98.10.79 was likely the C2 (Command and Control) server.

With this knowledge, I decided to gather all necessary information about the victim. I used different packets, such as NBNS and KRB5, and cross-referenced them to find the IP address, MAC address, hostname, and user account. Unfortunately, I was unable to find the correct username even after consulting the answers provided in the exercise site.

Next, I attempted to determine how the malware could have found its way onto the victim's PC. However, the traffic from both 199.232.196.209 and 185.199.110.133 was encrypted, making it impossible to identify the site responsible for the infection or the specific malware file itself. Both IP addresses and domains remain tagged as suspicious.

Finally, I explored "File" -> "Export Objects" -> "HTTP" to see if there was anything notable. I discovered ip-api.com, which I had missed while searching for connections outside the LAN. This site can be used to find geolocation data for IP addresses. Since this site was accessed after the host was infected, it’s important to save it as a potential IOC (Indicator of Compromise).


Executive Summary:

On 30 July 2024 around 2:40 UTC PC of user Clark Collier was infected with STRRAT malware
_________________________________________________________________________________________

Victim Details:

Ip address: 172.1.16.66

Hostname: DESKTOP-SKBR25F

MAC address: 00:1e:64:ec:f3:08

Windows user account name: ccollier (previously I incorrectly wrote desktop-skbr25f)
____________________________________________________________________________________

Indicators of compromise (IOCs)

Ip addresses And URL (potential cause of infection) : 199.232.196.209->repo1.maven.org, 185.199.110.133->objects.githubusercontent.com

Potential C2 server (post infection) : 141.98.10.79

IP checking: ip-api.com (application/JSON)


