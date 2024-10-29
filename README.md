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
  
At first I brifly scanned through to understand what I will be dealing with. I saw a lot of TLS encrypted traffic, so I tried to find Encryption Key Log File for this exercise. There wasn't one so I knew i would not be able to decrypt this traffic. Next I tried to look for start of any connection between one of host to host outside of LAN. While doing so I saw a lot of diffrent, and potentionaly suspicious ip addresses and domain names (141.98.10.79, 199.232.196.209->repo1.maven.org and 185.199.110.133->objects.githubusercontent.com). All of them where communicating with ip 172.16.1.66, so at that point I suspected that this host will be the victim. Next I checked tcp stream for all of these communications. I didn't expect to find a lot, most of them were TLS encrypted, but stream for 141.98.10.79 wasn't. In there I saw evidence of malware infection, more specificly STRRAT infection. So I then knew that 172.16.1.66 is the host that is infected and that 141.98.10.79 is most likekly C2 server. With that knowledge I decided to look for all required information about the victim. I used diffrent packets like NBNS and KRB5 and cross examined them to find ip, MAC, hostname and user account. Unfortunately later after looking at anwers file found in the exercise site, I was unable to find correct user name. Next I tried to see how the malware could possibly find itself on the victims pc, but because the traffic from both 199.232.196.209 and 185.199.110.133 were both encrypted I wasn't able to determine which one was the site that infected the pc and wasn't able to find the malware file itself. Both ip addresses and domains are tagged as suspicious. At last I went into "File"->"Export Objects"->"HTTP" to see if there is something to see there. I was able to find ip-api.com that I for some reason missed while searching for connections outside of LAN. This site give you ability to e.g. find geolocation data for IP addresses. This site was open after host was infected so it's important save it as potentional IOC.


Executive Summary:

On 30 July 2024 around 2:40 UTC PC of user Clark Collier was infected with STRRAT malware


Victim Details:

Ip address: 172.1.16.66

Hostname: DESKTOP-SKBR25F

MAC address: 00:1e:64:ec:f3:08

Windows user account name: ccollier (previously I incorrectly wrote desktop-skbr25f)


Indicators of compromise (IOCs)

Ip addresses And URL (potential cause of infection) : 199.232.196.209->repo1.maven.org, 185.199.110.133->objects.githubusercontent.com

Potential C2 server (post infection) : 141.98.10.79

IP checking: ip-api.com (application/JSON)


