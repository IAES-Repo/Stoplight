'''

Copyright (c) 2017- 2025 Python Forensics and Chet Hosmer

A non-exclusive perpetual license is hereby granted free of charge to the University of Arizona.

The above copyright notice and this permission notice shall be included in all copies or substantial 
portions of the Software.

Revision History

SPECIAL NOTE:  This script is experimental
V 1.0 December 2017
V 1.2 May 2021
V 2.0 Jan 2022
V 2.1 August 2022
V 2.2 November 2022
V 2.3 SENSOR - MAY 2023
V 2.4 SENSOR - JUNE 2023 CORRECTED BUG missingList
V 2.5 SENSOR - JUNE 2023 CORRECTED BUG ICMP Processing
v 2.6/2.7 SENSOR - JULY 2023 CORRECTED ICMP AND ARP BUGS

=====
v2 FM-CMD-v2 FM-SENSOR CommandLine Version - October 2023
v3 FM-CMD-V3 Update October 24, 2023
             Update to support pcap or nic processing 
             Update to generate a seperate Alert.txt File
V4 FM-CMD-V4 Updated the generation of the Alert File
v7 FM-CMD-V7 Modified size of TCPDUMP to 50GB maximum
             Added addition Event Log Messages for debugging
v8 FM-CMD-v8 Changes TCPDUMP to create multiple dump files for 
             processing.  Also, added additional Event Log Messages
             corrected issues with the Alerts File.  Note this
             version does not support passing individual PCAP files
             from the command line, it only supports network captures
v9 FM-CMD-v9 Fixed issues with processing local pcap file
             Added BLE Alert Method
V10 FM-CMD-V10: Fixed MAC address issue to report the full MAC
                Fixed Missing Suspect Port
                Added Alerts for New MAC Addresses
                Changed the ALERT Codes"
                      NEW-CONNECTION             = "NC"
                      NEW-DEVICE                 = "ND"
                      FOREIGN-COUNTRY            = "FC"
                      FOREIGN-COUNTRY-HOSTILE    = "FH"
                      FOREIGN-COUNTRY-DANGEROUS  = "FD"
                      SUSPECT-PORT               = "SP"
                      ABNORMAL-TRANSPORT         = "AT"
V11 FM-CMD-V11: Added Support for Diode Transfere
                Removed extraneous results .csv files
                NOTE: Must install psutil library 
                      pip3 install psutil
V12 FM-cmd-V12: Added an OPTIONAL switch to copy PCAP Files to Save Folder 
                the -s switch will copy PCAPS after capture once per hour.
                
V13 FM-cmd-V13: Removed the switch and hard coded the PCAP Save Function, 
                Also revoved the diode function and copied the PCAP file
                using the cmd line vs a library
V14 FM-cmd-V14-PCAP-Forever:
                When the -p option processing PCAPs in the ./PCAP folder
                will run forever.  In other words, it will process PCAP files
                as they appear in the ./PCAP folder and once processed it
                will delete the PCAP and wait for new PCAP files to appear
                
V15 FM-cmd-V15-Save PCAPS - Experimental
                1:This version does not delete PCAP files, rather once processed
                the pcap filename is prefixed with x_ 
                2:In addition, I added Remote IP connection alerts that are typically
                processed by the Analysis Script they will be identified as
                SENSOR-REMOTE-IP
                3:Finally, I noticed an issue when identifying suspicous port usage
                and corrected this to ensure alerts are generated regarding 
                these ports and will be identified as SUSPECT-PORT

V16 FM-cmd-V16-Save PCAP

                Corrected Version, with test code removed.
                
V17 FM-cmd-v17-PCAP-SIGNAL
            ADDED SIGNAL GENERATION BACK IN
                
Written exclusively for Python 3.x.x or above

Overview:

The script launches TCPDump with specified parameters
to sniff packets.  The network nic should be configured
for LINKLOCAL to avoid any packets entering the network
being sniffed.

Initially the Script will capture traffic for 60 minutes
at the top of the hour. then process the generated PCAP 
producing an ICS Report for that hour.  The script will
then restart capturing traffic.

'''
# Python Standard Library Module Imports
import signal            # Used to signal Diode
import psutil            # pip or pip3 install psutil
import sys               # System specifics
import subprocess        # Support for subprocess functions
import platform          # Platform specifics
import os                # Operating/Filesystem Module
import io
import time              # Basic Time Module
import re                # Regular Expression Library
import logging           # Script Logging
import time              # Time Functions
import datetime          # Date/Time Methods
from datetime import datetime as dt
import pickle            # Object Serialization
import struct            # Parsing Binary Data Structures
from binascii import hexlify
from binascii import unhexlify
from subprocess import Popen, PIPE, run, CalledProcessError
import argparse
import ipaddress    # ipv4 and ipv6 manipulation library


'''
Python 3rd Party Library imports

Simple PCAP File 3rd Party Library 
to process pcap file contents

To install the Library
sudo pip install pypcapfile   # make sure to install as sudo
'''

from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network   import ip
from pcapfile.protocols.transport import tcp
from pcapfile.protocols.transport import udp

import netaddr      # Network Address Conversions
                    # sudo pip install netaddr  # make sure to install as sudo
                    
from prettytable import PrettyTable  # sudo pip install prettytable make sure to install as sudo              

# Script Constants

NAME    = "Passive Sensor "
VERSION = " Version November 2024 v13 Command Line"
AUTHOR  = "C. Hosmer"
TITLE   = NAME+'\t'+VERSION
DEBUG   = True

UDP_LEN  = 8    # UPD HEADER   LENGTH
TCP_LEN  = 20   # TCP HEADER   LENGTH

SYSTEM  = platform.system()
PYTHON  = sys.version[0:6]

# Key offsets
_SRCMAC=0   # Source MAC
_DSTMAC=1   # Destinatin MAC
_SRCPORT=2  # Source Port
_DSTPORT=3  # Destination Port
_PROT=4     # Protocol

# Value offsets
_SRCIP=0            # Src IP
_DSTIP=1            # Dst IP
_SRCMFG=2             # Src MFG
_DSTMFG=3             # Dst MFG
_SRCPORTDESC=4      # Src Port Description
_DSTPORTDESC=5      # Dst Port Description
_ICS=6              # ICS Traffic
_CLIST=7            # CountryList
_DLIST=8            # Day of Week List
_HRLIST=9          # Hour of Day List
_PCKCNT=10          # Total Packet Count
_ALERT=11           # Alert Value
_PCKSIZE=12         # Packet Size

# Screen Colors
BG = 'white'
FG = 'black'

if not os.path.isdir('./PCAP'):
    os.mkdir('./PCAP')
    os.chmod("./PCAP", 0o0777)

PCAPDIR = "./PCAP"
    
if not os.path.isdir('./LOG'):
    os.mkdir('./LOG')    

REPORTS = "./REPORTS"

if not os.path.isdir(REPORTS):
    os.mkdir(REPORTS)

ALERTS = "./ALERTS"
ALERT_FILE = ALERTS+"/ALERTS.TXT"

ALERTX = {}
ALERTX["UNKNOWN-ICS-CONNECTION"]     = "NC"
ALERTX["NEW-DEVICE"]                 = "ND"
ALERTX["FOREIGN-COUNTRY"]            = "FC"
ALERTX["FOREIGN-COUNTRY-HOSTILE"]    = "FH"
ALERTX["FOREIGN-COUNTRY-DANGEROUS"]  = "FD"
ALERTX["SUSPECT-PORT"]               = "SP"
ALERTX["ABNORMAL-TRANSPORT"]         = "AT"
ALERTX["SENSOR-REMOTE-IP"]           = "RI"

if not os.path.isdir(ALERTS):
    os.mkdir(ALERTS)

def getPID():
    try:
        # Run 'pgrep' to get the PID(s)
        pids = subprocess.check_output(['pgrep', "python"]).strip()
        # Convert to a list of PIDs (in case there are multiple matches)
        pidList = [int(pid) for pid in pids.splitlines()]
        pidFound = None
        for eachPID in pidList:
            processCmdLine =  getCmdLine(eachPID)
            if "udp_send_json" in processCmdLine[1]:
                pidFound = eachPID
        return pidFound
    except:
        return None

# Script Local Functions
def getCmdLine(pid):
    try:
        # Get process by PID
        process = psutil.Process(pid)
        return process.cmdline()
    except psutil.NoSuchProcess:
        return None
    
'''
InitLog: Initialize the Forensic Log

'''

def InitLog():

    try:            

        now = datetime.datetime.now()
        tm = now.strftime('%Y-%m-%d-%H-%M-%S-')
        logFolder = os.path.abspath('./LOG')
        logPath = os.path.join(logFolder, 'LOG '+tm+".txt")   

        # Initialize the Log include the Level and message
        logging.basicConfig(filename=logPath, format='%(levelname)s\t:%(message)s', level=logging.DEBUG)

        LogEvent("STARTUP LOG")
        
    except Exception as err:
        print(str(err))
        print()

# End of Forensic Log Initialization

# Function: LogEvent()
#
# Logs the event message and specified type
# Input: 
#        eventMessage : string containing the message to be logged

def LogEvent(eventMessage):

    try:

        if type(eventMessage) == str:

            re.sub(r'[^\x00-\x7f]',r'', eventMessage)         

            timeStr = GetTime('UTC')
            # Combine current Time with the eventMessage
            # You can specify either 'UTC' or 'LOCAL'
            # Based on the GetTime parameter

            eventMessage = str(timeStr)+": "+eventMessage
            logging.info(eventMessage)

    except:
        pass

# End LogEvent Function    

OVERWRITE = False        # Overwrite the Log on Each execution

# Screen Colors
BG = 'white'
FG = 'black'

XLATE_PORTS= ['80','135','1900','3011','53','389', '88']

# Script Local Functions

def TimeStampFileName(objName):

    ''' Create a filename with prefixed timestamp '''
    now = datetime.datetime.now()
    tm = now.strftime('%Y-%m-%d-%H-%M-%S-')

    fileName = tm+objName

    return fileName


# Function: GetTime()
#
# Returns a string containing the current time
#
# Script will use the local system clock, time, date and timezone
# to calcuate the current time.  Thus you should sync your system
# clock before using this script
#
# Input: timeStyle = 'UTC', 'LOCAL', the function will default to 
#                    UTC Time if you pass in nothing.

def GetTime(timeStyle = "UTC"):

    if timeStyle == 'UTC':
        return ('UTC Time:  ', time.asctime(time.gmtime(time.time()))) 
    elif timeStyle == 'LOCAL':
        return ('Local Time:', time.asctime(time.localtime(time.time())))
    else:
        return "Invalid TimeStyle Specified"

# End GetTime Function       

class RangeDict(dict):
    ''' Convert dictionary to a range dictionary '''
    def __getitem__(self, item):
        if type(item) != range: 
            for key in self:
                if item in key:
                    return self[key]
        else:
            return super().__getitem__(item)


class ETH:
    
    def __init__(self):
    
        self.ethTypes = {}
        
        self.ethTypes[2048]   = "IPv4"
        self.ethTypes[2054]   = "ARP"
        self.ethTypes[34525]  = "IPv6"
            
    def lookup(self, ethType):
        
        try:
            result = self.ethTypes[ethType]
        except:
            result = "not-supported"
            
        return result

#ICS MAC  Lookup Class
class ICSMAC:
   
    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('./SUPPORT/ouiICS.pickle', 'rb') as pickleFile:
            self.macICSDict = pickle.load(pickleFile)
            
    def isICS(self, macAddress):
        
        try:
            result = self.macICSDict[macAddress]
            return True
        except:
            return False
           
# MAC Address Lookup Class
class MAC:

    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('./SUPPORT/oui.pickle', 'rb') as pickleFile:
            self.macDict = pickle.load(pickleFile)
        '''
        if DEBUG:
            for key, value in self.macDict.items():
                print(key, value)
            print()
        '''
            
    def lookup(self, macAddress):
        
        if macAddress.startswith('FFFF'):
            return("BROADCAST")
        
        if macAddress.startswith('3333'):
            return("ipv6 Multicast")
        
        if macAddress.startswith('0100'):
            return("CISCO Discovery")
        
        if macAddress.startswith('DCA632'):
            return("RASPBERRY PI")
        
        if macAddress.startswith('003018'):
            return("Jetway Information Ltd. Tiawain")     
        
        if macAddress.startswith('001517'):
            return("Intel Corp Malaysia")        
        
        try:
            result = self.macDict[macAddress]
            return result
        except:
            return "NA"
        
# Transport Lookup Class

class TRANSPORT:

    def __init__(self):
        
        # Open the transport protocol Address OUI Dictionary
        with open('./SUPPORT/protocol.pickle', 'rb') as pickleFile:
            self.proDict = pickle.load(pickleFile)

    def lookup(self, protocol):
        try:
            result = self.proDict[protocol]
            return result
        except:
            return ["unknown", "unknown", "unknown"]

#PORTS Lookup Class

class PORTS:

    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('./SUPPORT/PortsPicklewHostile.db', 'rb') as pickleFile:
            self.portDict = pickle.load(pickleFile)
        self.portDict[('47810', 'UDP')] = ['Building Automation and Control Networks', 'OK']

    def lookup(self, port, portType):
        try:
            result = self.portDict[(port,portType)]
            desc = result[0]
            alertResult = result[1]
            if "OK" in alertResult[0:3]:
                alert = ""
                alertDesc = ""
            else:
                alert = "SUSPECT-PORT"
                alertDesc = alertResult[5:]
            return desc, alert, alertDesc
        except:
            return "EPH"+":"+port, "", ""

class ICSPORTS:

    def __init__(self):
        
        # Open the MAC Address OUI Dictionary
        with open('./SUPPORT/icsPorts.db', 'rb') as pickleFile:
            self.icsPortsDict = pickle.load(pickleFile)
        '''
        if DEBUG:
            for key, value in self.icsPortsDict.items():
                print(key, value)
            print()
        '''
        
    def lookup(self, port, portType):
        try:
            result = self.icsPortsDict[(portType, port)]
            return True
        except:
            return False


class COUNTRY:
    ''' Country Lookup Class '''

    def __init__(self):
        
        ''' Load the ip lookup databases '''
        try:
            ipData = open('./SUPPORT/ccLookup.db', 'rb')    # Open the lookup DB
            self.ipCheck = pickle.load(ipData)
            ''' Load the Country/Category lookup data provided '''
            catData = open('./SUPPORT/ccCategory.db', 'rb')    # Open the lookup DB
            self.ccCategory = pickle.load(catData)
            
        except Exception as err:
            sys.exit('Error Loading Required Databases: '+str(err))
            
         
        #self.cc = {}
        #self.ccCat = {}
        
    def isValid(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except Exception as err:
            return False
    def isPrivate(self,ip):
        ''' Check for private and link local addresses '''
        try:
            if ipaddress.ip_address(ip).is_private:
                return True
            else:
                return False
        except Exception as err:
                return False
    
    def isReserved(self, ip):
        try:
            if ipaddress.ip_address(ip).is_reserved:
                return True
            else:
                return False
        except Exception as err:
            return False
    
    def isMulticast(self, ip):
        try:
            if ipaddress.ip_address(ip).is_multicast:
                return True
            else:
                return False
        except Exception as err:
            return False    
        
    def isLoopBack(self, ip):
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return True
            else:
                return False
        except Exception as err:
            return False   
        
    def isLinkLocal(self, ip):
        try:
            if ipaddress.ip_address(ip).is_link_local:
                return True
            else:
                return False
        except Exception as err:
            return False
        
    def lookup(self, ipAddr):
        '''
        lookup the country information relating to the provided ipAddress
        ipAddr must be in the standard dotted notation.  i.e. 205.232.34.1
        '''
        try:
        
            if ipAddr.startswith('192.') or ipAddr.startswith('10.0') or ipAddr.startswith('172.') or ipAddr.startswith('224.') or ipAddr.startswith('fe80') or ipAddr.startswith('ff02'):
                return '', 'Local', ''
            
            ipInt = int(netaddr.IPAddress(ipAddr))  # Convert dotted notation to integer
            try:
                cc = self.ipCheck[ipInt]                     # Lookup the ip address
            except:            
                return '', '', ''
            
            if cc == '' or cc == 'ZZ':
                if not self.isValid(ipAddr):
                    cc       = "Invalid"
                    name     = "Invalid"
                    category = "Invalid"
                    return cc, name, category
                
                elif self.isReserved(ipAddr):
                    cc       = "Reserved"
                    name     = "Reserved"
                    category = "Reserved"
                    return cc, name, category
                
                elif self.isLinkLocal(ipAddr):
                    cc       = "Local"
                    name     = "Local"
                    category = "Local"         
                    return cc, name, category
                
                elif self.isPrivate(ipAddr):
                    cc       = ""
                    name     = "Private"
                    category = ""       
                    return cc, name, category
                
                elif self.isLoopBack(ipAddr):
                    cc       = "Loopback"
                    name     = "Loopback"
                    category = "Local"   
                    return cc, name, category
                    
                elif self.isMulticast(ipAddr):
                    cc       = "Multicast"
                    name     = "Multicast"
                    category = "Local"   
                    return cc, name, category
                else:
                    return '', '', ''

            else:
                try:                                # Lookup CC Translation
                    v = self.ccCategory[cc]
                    name = v[0]
                    category = v[1]                          
                    return cc, name, category
                except:                     
                    if not self.isValid(ipAddr):
                        cc       = "Invalid"
                        name     = "Invalid"
                        category = "Invalid"
                        return cc, name, category
                    
                    elif self.isReserved(ipAddr):
                        cc       = "Reserved"
                        name     = "Reserved"
                        category = "Reserved"
                        return cc, name, category
                    
                    elif self.isLinkLocal(ipAddr):
                        cc       = "Local"
                        name     = "Local"
                        category = "Local"         
                        return cc, name, category
                    
                    elif self.isPrivate(ipAddr):
                        cc       = "Private"
                        name     = "Private"
                        category = "Private"       
                        return cc, name, category
                    
                    elif self.isLoopBack(ipAddr):
                        cc       = "Loopback"
                        name     = "Loopback"
                        category = "Local"   
                        return cc, name, category
                        
                    elif self.isMulticast(ipAddr):
                        cc       = "Multicast"
                        name     = "Multicast"
                        category = "Local"   
                        return cc, name, category
                    else:
                        return '', '', ''

    
        except Exception as err:
            return '', '', ''
        


class IPObservationDictionary:

    # Constructor
    
    def __init__(self):
        
        #Attributes of the Object
        
        self.Dictionary = {}            # Dictionary to Hold IP Observations
        self.portObservations = {}
        self.ipConnectionSet = set()
        self.AlertDictionary = {}       # Added Alert Dictionary
        
        
    # Method to Add an observation
    
    def AddOb(self, key, srcIP, dstIP, srcMFG, dstMFG, srcPortDesc, dstPortDesc, ics, countryList, when, alert, ts, pckSize):
                   
        # Check to see if key is already in the dictionary
            
        hr  = when[0]   # when[0] == hour 0-23
        day = when[1]   # when[1] == day 0-6
        ts  = when[2]   # Detailed Timestamp
        
        srcMAC        = key[_SRCMAC]
        dstMAC        = key[_DSTMAC]
        srcPORT       = key[_SRCPORT]
        dstPORT       = key[_DSTPORT]
        protocol      = key[_PROT]
        if ics:
            icsTraffic = "YES"
        else:
            icsTraffic = "No"
        
        srcCountryCategory = "SrcCountry: "+ countryList[1]
        dstCountryCategory = "DstCountry: "+ countryList[4]
        countryDetails = srcCountryCategory+" --> "+dstCountryCategory
        
        if key in self.Dictionary:
        
            # If yes, retrieve the current value
            curValue = self.Dictionary[key]

            srcIP         = curValue[_SRCIP]
            dstIP         = curValue[_DSTIP]
            srcMFG        = curValue[_SRCMFG]
            dstMFG        = curValue[_DSTMFG]
            curSrcPortDesc = curValue[_SRCPORTDESC]
            curDstPortDesc = curValue[_DSTPORTDESC]
            ics            = curValue[_ICS]
            curCountry     = curValue[_CLIST]
            dayList        = curValue[_DLIST]
            hrList         = curValue[_HRLIST]
            pckCnt         = curValue[_PCKCNT]
            alert          = curValue[_ALERT]
            totalPckSize   = curValue[_PCKSIZE]
            
            dayList[day] += 1
            hrList[hr]   += 1
            totalPckSize += pckSize
            
            pckCnt = sum(dayList)
            
            # Update the value associated with this key
            self.Dictionary[key] = [srcIP, dstIP, srcMFG, dstMFG, curSrcPortDesc, curDstPortDesc, ics, curCountry, dayList, hrList, pckCnt, alert, totalPckSize]
                
        else:
            # if the key doesn't yet exist
            # Create one
            
            dayList = [0] * 7 
            hrList  = [0] * 24            

            dayList[day] = 1
            hrList[hr]   = 1
                
            self.Dictionary[key] = [srcIP, dstIP, srcMFG, dstMFG, srcPortDesc, dstPortDesc, ics, countryList, dayList, hrList,  1, alert, pckSize]

        ''' IF ALERT IS PRESENT UPDATE THE ALERT DICTIONARY '''
        
        fill = ": "
        if alert:
            alertCode = ALERTX[alert]
            alertKey = (ts, alertCode)
            self.AlertDictionary[alertKey] = [protocol, srcMAC, srcMFG, dstMAC, dstMFG, srcIP, srcPORT, srcPortDesc, dstIP, dstPORT, dstPortDesc, countryDetails, str(pckSize)]
            bleMsg = [alertCode+fill+ts,
                      "PROTO:"+protocol,
                      "SRCMAC:"+srcMAC,
                      "DSTMAC:"+dstMAC,
                      "SRCIP:"+srcIP,
                      "DSTIP:"+dstIP,
                      "SRCPORT:"+srcPORT,
                      "DSTPORT:"+dstPORT,
                      "PCKSIZE:"+str(pckSize)
                      ]
            '''
            for eachbleSegment in bleMsg:
                print(len(eachbleSegment), eachbleSegment) 
            '''
            
    def AddPortOb(self, key, desc, when, ts, ICSFLAG):
     
        hr  = when[0]   # when[0] == hour 0-23
        day = when[1]   # when[1] == day 0-6     

        
        if key in self.portObservations:
            
            curValue = self.portObservations[key]
            
            desc       = curValue[0]
            dayList    = curValue[1]
            hrList     = curValue[2]
            total      = curValue[3]  
            
            dayList[day] += 1
            hrList[hr]   += 1
            
            total = sum(hrList)            
            
            self.portObservations[key] = [desc, dayList, hrList, total, ICSFLAG]
        else:
            dayList = [0] * 7 
            hrList  = [0] * 24            
            dayList[day] = 1
            hrList[hr]   = 1
            total = sum(hrList)  
                        
            self.portObservations[key] = [desc, dayList, hrList, total, ICSFLAG]
        
    def CreateJSONandCSV(self, path):

        diodePID = getPID()
        
        observationtbl = PrettyTable(['ALERT','ICS', 'PROTOCOL', 'SRCIP', 'DSTIP', 'SRCPORT', 'SRCPORTDESC','DSTPORT', 'DSTPROTDESC',  
                                      'SRCMAC', 'SRCMFG', 'DSTMAC', 'DSTMFG', 'SRCCC', 'DSTCC','...',
                                      'TOTPACKETS','TOTDATA','MON','TUE','WED','THU','FRI','SAT','SUN',
                                      '12AM','1AM','2AM','3AM','4AM','5AM','6AM','7AM','8AM','9AM','10AM','11AM',
                                      '12PM','1PM','2PM','3PM','4PM','5PM','6PM','7PM','8PM','9PM','10PM','11PM'])
        
        icsConnections = PrettyTable(['ALERT','PROTOCOL', 'SRCMAC', 'SRCMFG', 'DSTMAC','DSTMFG', 'SRCIP', 'SRCPORT', 'SRCPORTDESC', 'DSTIP', 
                                      'DSTPORT', 'DSTPORTDESC', 
                                      'TOTPACKETS','TOTDATA','MON','TUE','WED','THU','FRI','SAT','SUN'])
        
        icsAlerts = PrettyTable (['TS', "ALERT", 'PROTOCOL', 'SRCMAC', 'SRCMFG', 'DSTMAC', 'DSTMFG', 'SRCIP', 'SRCPORT', 'SRCPORTDESC', 'DSTIP', 
                                      'DSTPORT', 'DSTPORTDESC', 'COUNTRYDETAILS', 'PACKETSIZE'])
        
        for k, v in self.AlertDictionary.items():
            row = [k[0], k[1], v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],v[8], v[9], v[10], v[11], v[12]]
            icsAlerts.add_row(row)
            
        for k, v in self.Dictionary.items():
            
            srcPort = k[_SRCPORT]
            dstPort = k[_DSTPORT]
            srcMAC    = k[_SRCMAC].upper()              
            dstMAC    = k[_DSTMAC].upper()            

            try:    
                protocol= '{:5s}'.format(k[_PROT])  
            except:
                protocol = ""
                        
            if v[6]:
                ICS="**"
            else:
                ICS=""
                
            dayList     = v[_DLIST]
            hrList      = v[_HRLIST]
            total       = v[_PCKCNT]       
            alert       = v[_ALERT]
            totSize     = '{:6.2f}'.format((v[_PCKSIZE]/1000000))+" MB"
            
            srcIP = '{:14s}'.format(v[_SRCIP])
            dstIP = '{:14s}'.format(v[_DSTIP])
            srcPortDesc = v[_SRCPORTDESC]
            dstPortDesc = v[_DSTPORTDESC]

            countryData = v[_CLIST]
            
            srcMFG    = v[_SRCMFG]
            dstMFG    = v[_DSTMFG]
            srcMFG    = v[_SRCMFG]
            dstMFG    = v[_DSTMFG]            

            srcCat        = countryData[2]
            dstCat        = countryData[5]            
            srcCountry    = countryData[1]+"-"+srcCat
            dstCountry    = countryData[4]+"-"+dstCat

            row = [alert, ICS, protocol, srcIP, dstIP, srcPort, srcPortDesc, dstPort, dstPortDesc, srcMAC, srcMFG, dstMAC, dstMFG,
                       srcCountry, dstCountry, '...', total, totSize]
            
            for eachDay in dayList:
                row.append(eachDay)
                
            for eachHr in hrList:
                row.append(eachHr)
            
            observationtbl.add_row(row)
            
            if ICS == "**":
                icsRow = [alert, protocol, srcMAC, srcMFG, dstMAC, dstMFG, srcIP, srcPort, srcPortDesc, dstIP, dstPort, dstPortDesc, total, totSize]
                for eachDay in dayList:
                    icsRow.append(eachDay)
                icsConnections.add_row(icsRow)
                
        observationtbl.title = 'Packet Observations'
        observationtbl.align = 'l'
        
        icsConnections.title = "ICS Connection Observations"
        icsConnections.align = 'l'   
        
        icsAlerts.title = "ICS ALERTS"
        icsAlerts.align = 'l'
        
        portsTbl = PrettyTable(['IP', 'PORT', '...',
                                      'TOTAL', 'MON','TUE','WED','THU','FRI','SAT','SUN',
                                      '12AM','1AM','2AM','3AM','4AM','5AM','6AM','7AM','8AM','9AM','10AM','11AM',
                                      '12PM','1PM','2PM','3PM','4PM','5PM','6PM','7PM','8PM','9PM','10PM','11PM'])
                
        # Output that file
        
        rObsJSON      = observationtbl.get_json_string()
        icsObsJSON    = icsConnections.get_json_string()  
        icsAlertsJSON = icsAlerts.get_json_string()
        
        rObsCSV      = observationtbl.get_csv_string()
        icsObsCSV    = icsConnections.get_csv_string()  
        icsAlertsCSV = icsAlerts.get_csv_string()
        
        # CREATE IP OBSERVATIONS JSON     
        
        # ALL CONNECTIONS
        allObsALLJSON = TimeStampFileName("jsonALLConnections.json")
        allObsALLJSONFilename = os.path.join(REPORTS, allObsALLJSON)         
        
        with open(allObsALLJSONFilename, 'w') as output:
            print(rObsJSON, file=output)   
            
        # ICS CONNECTIONS
        allObsICSJSON = TimeStampFileName("jsonICSConnections.json")
        allObsICSJSONFilename = os.path.join(REPORTS, allObsICSJSON)          
        
        with open(allObsICSJSONFilename, 'w') as output:
            print(icsObsJSON, file=output)           
            
        # ALERTS
        allICSAlertsFileName = TimeStampFileName("jsonICSAlerts.json")
        icsAlertsFilename = os.path.join(ALERTS, allICSAlertsFileName)         
        
        with open(icsAlertsFilename, 'w') as output:
            print(icsAlertsJSON, file=output)      
                     
        if diodePID:
            # Send SIGUSR1 to the target process
            os.kill(diodePID, signal.SIGUSR1)            
            
            
    # Destructor Delete the Object
    
    def __del__(self):
        '''
        if DEBUG:
            print ("Closed")
        '''
        
# End IPObservationClass ====================================


class StartUp():

    def __init__(self, NIC, PCAPFILE, KNOWN_CONNECTIONS, INTERVAL):

        # Define the instance variables to be
        # collected from the GUI

        self.pcapFolder   = PCAPDIR 
        
        if NIC != None:
            
            leftOverPCAPs = os.listdir(self.pcapFolder)
            
            for eachPCAP in leftOverPCAPs:
                rmPCAP = os.path.join(self.pcapFolder, eachPCAP)
                try:
                    LogEvent("Removing OLD PCAP File: "+rmPCAP)  
                    os.remove(rmPCAP)  
                except Exception as err:
                    LogEvent("Removing OLD PCAP File Failed: "+str(err)+", "+rmPCAP)
                continue              

        
        self.ReportFolder = REPORTS
        self.abortFlag    = False
        
        # Create Lookup Objects
        self.macOBJ    = MAC()
        self.icsMACOBJ = ICSMAC()
        self.traOBJ    = TRANSPORT()
        self.portOBJ   = PORTS()
        self.ethOBJ    = ETH()     
        self.cc        = COUNTRY()
        self.icsPortsOBJ = ICSPORTS()
        
        self.NIC = NIC
        
        with open(KNOWN_CONNECTIONS, "rb") as infile:
            self.KNOWN_CONNECTIONS = pickle.load(infile)       
            
        self.INTERVAL = INTERVAL
        
    def ProcessPCAP(self):
    
        pcapList = os.listdir(self.pcapFolder)

        pktCnt          = 0            
        self.macIPDict  = {} 
        
        # Create IP observation dictionary object   
        self.ipOB = IPObservationDictionary()         
        
        self.StartTime = GetTime()            
        pTime = time.time()
        
        for pcap in pcapList:
            
            # Skip already processed pcap files
            if pcap.startswith("x_"):
                continue
                            
            self.targetFile = os.path.join(PCAPDIR, pcap)
            

            if DEBUG:
                print("Processing "+self.targetFile)
            
            try:
                icsCapture = open(self.targetFile, 'rb')
                capture = savefile.load_savefile(icsCapture, layers=0, verbose=False)
                LogEvent("Processing PCAP: "+self.targetFile+" PCK-CNT: "+str(len(capture.packets)))
                print("Processing PCAP: "+self.targetFile+" PCK-CNT: "+str(len(capture.packets)))
            except Exception as err:
                # Unable to ingest pcap   
                LogEvent("LOAD PCAP Failed: "+self.targetFile)
                try:
                    LogEvent("Attempting to Remove invalid PCAP File: "+self.targetFile)  
                    os.remove(self.pcapFile)  
                except Exception as err:
                    LogEvent("Removing invalid PCAP File Failed: "+str(err)+", "+self.targetFile)
                continue
            
            # Now process each packet
            for pkt in capture.packets:
                
                pktCnt += 1
                
                timeStruct = time.gmtime(pkt.timestamp)
                iso = time.strftime('%Y-%m-%d %H:%M:%SZ', timeStruct)

                # extract the hour the packet was captured
                theHour   = timeStruct.tm_hour      
                theWkDay  = timeStruct.tm_wday
                
                when = [theHour, theWkDay, iso]
                
                # Get the raw ethernet frame
                ethFrame = ethernet.Ethernet(pkt.raw())
                packetSize = pkt.packet_len
                
                alert = ""
                
                '''
                Ethernet Header
                0                   1                   2                   3                   4              
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                                      Destination Address                                      |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                                         Source Address                                        |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |           EtherType           |                                                               |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                               +
                |                                                                                               |
                +                                            Payload                                            +
                |                                                                                               |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            
                '''
                    
                ''' ---- Extract the source mac address ---- '''
                fullSrcMAC     = "".join(map(chr, ethFrame.src))
                fullSrcMAC     = fullSrcMAC.upper()
                
                srcMAC     = fullSrcMAC[0:8].upper()
                # remove the colon seperators
                # note the variable names starting with fld, we will use these later
                fldSrcMAC  = re.sub(':','',srcMAC) 
                
                # Attempt to lookup the mfg in our lookup table 
                fldSrcMFG  = self.macOBJ.lookup(fldSrcMAC)    
                icsSrcMac  = self.icsMACOBJ.isICS(fldSrcMAC)
                
                ''' Extract the destination mac address ---'''
                fullDstMAC     = "".join(map(chr, ethFrame.dst))
                fullDstMAC     = fullDstMAC.upper()
                
                dstMAC     = fullDstMAC[0:8].upper()
                # remove the colon seperators
                # note the variable names starting with fld, we will use these later
                fldDstMAC  = re.sub(':','',dstMAC) 
                
                # Attempt to lookup the mfg in our lookup table 
                fldDstMFG  = self.macOBJ.lookup(fldDstMAC)     
                icsDstMac  = self.icsMACOBJ.isICS(fldDstMAC)
                
                icsSrcFlag = False
                icsDstFlag = False
                
                unknownConnection = ""
                
                if icsSrcMac or icsDstMac:
                    icsFlag = True
                    if icsSrcMac:
                        icsSrcFlag = True
                    if icsDstMac:
                        icsDstFlag = True
                    srcDst = [fullSrcMAC, fullDstMAC]
                    dstSrc = [fullDstMAC, fullSrcMAC]
                    
                    if srcDst in self.KNOWN_CONNECTIONS or dstSrc in self.KNOWN_CONNECTIONS:
                        unknownConnection = ""
                    else:
                        unknownConnection = "UNKNOWN-ICS-CONNECTION"
                else:
                    icsFlag = False
            
                ''' --- create a list of mac addresses and manufacture ouis '''
                macData = [fullSrcMAC, fldSrcMFG, fullDstMAC, fldDstMFG]
            
                ''' Lookup the Frame Type '''
                frameType = self.ethOBJ.lookup(ethFrame.type)
                
                ''' Process any IPv4 Frames '''
               
                if frameType == "IPv4":
                    '''
                    ipV4 Header
                    0                   1                   2                   3  
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |Version|  IHL  |Type of Service|          Total Length         |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |         Identification        |Flags|     Fragment Offset     |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |  Time to Live |    Protocol   |        Header Checksum        |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                         Source Address                        |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                      Destination Address                      |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                    Options                    |    Padding    |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   
                    '''
                    
                    ''' Extract the payload '''
                    ipPacket = ip.IP(unhexlify(ethFrame.payload))
                    ttl = ipPacket.ttl
                        
                    ''' Extract the source and destination ip addresses '''
                    srcIP = "".join(map(chr,ipPacket.src))
                    dstIP = "".join(map(chr,ipPacket.dst))
                    
                    tstSRC = srcIP[0:3]
                    tstDST = dstIP[0:3]    
                    
                    ''' Extract the protocol in use '''
                    protocol = str(ipPacket.p)                    
                    
                    if DEBUG:

                        if tstSRC == '107' or tstDST == '107':
                            print(tstSRC, tstDST)                            
                    
                    self.macIPDict[(fullSrcMAC, srcIP)] = fldSrcMFG
                    self.macIPDict[(fullDstMAC, dstIP)] = fldDstMFG
                    
                    self.srcCC, self.srcCountryName, self.srcCategory,  = self.cc.lookup(srcIP)
                    self.dstCC, self.dstCountryName, self.dstCategory   = self.cc.lookup(dstIP)
                    
                    if self.srcCategory == "HOSTILE" or self.dstCategory == "HOSTILE":
                        alertCC = 'COUNTRY-HOSTILE'
                    else:
                        alertCC = ''
                    
                    if not alertCC:
                        if self.srcCategory == "FOREIGN" or self.dstCategory == "FOREIGN":
                            alertCC = 'COUNTRY-FOREIGN'
                        else:
                            alertCC = ''      
                            
                    if not alertCC:
                        if self.srcCategory == "DANGEROUS" or self.dstCategory == "DANGEROUS":
                            alertCC = 'COUNTRY-DANGEROUS'
                        else:
                            alertCC = ''                          
                    
                    countryDetails = [self.srcCC, self.srcCountryName, self.srcCategory, self.dstCC, self.dstCountryName, self.dstCategory]
                    
                    try:
                        REMOTE_CONNECION = False
                        if not alertCC:   # Check for Remote IP
                            validIP = ['192','244', '224', '239','10.', '128', 'ff0', 'fe8']
                            
                            if srcIP and dstIP:
                                if protocol != 'ARP':   # Ignore ARP                                     
                                    if not tstSRC in validIP or not tstDST in validIP:
                                        REMOTE_CONNECION = True
                                    else:
                                        REMOTE_CONNECION = False 
                    except:
                        pass

                    ''' Lookup the transport protocol in use '''
                    transport = self.traOBJ.lookup(protocol)[0]
                    
                    if transport == "TCP":
                        
                        '''
                        TCP HEADER
                        0                   1                   2                   3  
                        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |          Source Port          |        Destination Port       |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |                        Sequence Number                        |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |                     Acknowledgment Number                     |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        | Offset|  Res. |     Flags     |             Window            |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |            Checksum           |         Urgent Pointer        |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        |                    Options                    |    Padding    |
                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                        '''
                        
                        tcpPacket = tcp.TCP(unhexlify(ipPacket.payload))
                        
                        srcPort = tcpPacket.src_port
                        dstPort = tcpPacket.dst_port
                        
                        # Lookup Port Description, if not found assume Ephemeral 
                        srcPortDesc, alertSRCPort, alertSRCPortDesc = self.portOBJ.lookup(str(srcPort), "TCP")
                        
                        if "EPH" in srcPortDesc:
                            srcPort = "EPH"
                        else:
                            srcPort = str(srcPort)
                        
                        if srcPort in XLATE_PORTS:
                            dstPortDesc = "EPH"
                      
                        dstPortDesc, alertDSTPort, alertDSTPortDesc = self.portOBJ.lookup(str(dstPort), "TCP")
                                    
                        if "EPH" in dstPortDesc:
                            dstPort = "EPH"
                        else:
                            dstPort = str(dstPort)                                    
                            
                        if dstPort in XLATE_PORTS:
                            srcPortDesc = "EPH"    
                            
                        if "building automation" in srcPortDesc.lower():
                            srcPortDesc = "BACnet"
                            
                        if "building automation" in dstPortDesc.lower():
                            dstPortDesc = "BACnet"                     
                            
                        if alertCC:
                            alert = alertCC
                        elif alertSRCPort:
                            alert = alertSRCPort
                        elif alertDSTPort:
                            alert = alertDSTPort
                        elif unknownConnection:
                            alert = unknownConnection   
                        elif REMOTE_CONNECION:
                            alert = "SENSOR-REMOTE-IP"
                        else:
                            alert = ""
                            
                        # Add a new IP observation and the hour
                        srcMAC = macData[0]
                        srcMFG = macData[1]
                        dstMAC = macData[2]
                        dstMFG = macData[3]
                        
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, srcPort, dstPort, "TCP"), srcIP, dstIP, srcMFG, dstMFG, srcPortDesc, dstPortDesc, icsFlag, countryDetails, when, alert, iso, packetSize)
                           
                        # Post them to PortObject Dictionary
                        if srcPort != "EPH":
                            self.ipOB.AddPortOb((srcIP, srcPort), srcPortDesc, when, iso, icsSrcFlag)
                        if dstPort != "EPH":
                            self.ipOB.AddPortOb((dstIP, dstPort), dstPortDesc, when, iso, icsDstFlag)
                            
                    elif transport == "UDP":
                        '''
                         0                   1                   2                   3  
                         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                         |          Source Port          |        Destination Port       |
                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                         |             Length            |            Checksum           |
                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                         '''
                        
                        udpPacket = udp.UDP(unhexlify(ipPacket.payload))
                        
                        srcPort = udpPacket.src_port
                        dstPort = udpPacket.dst_port
                        payload = udpPacket.payload
                        
                        # Lookup Port Description, if not found assume Ephemeral 
                        srcPortDesc, alertSRCPort, alertSRCPortDesc = self.portOBJ.lookup(str(srcPort), "UDP")
                            
                            
                        if "EPH" in srcPortDesc:
                            srcPort = "EPH"
                        else:
                            srcPort = str(srcPort)
                            
                        if srcPort in XLATE_PORTS:
                            dstPortDesc = "EPH"
                    
                        dstPortDesc,alertDSTPort, alertDSTPortDesc = self.portOBJ.lookup(str(dstPort), "UDP")    
    
                        if dstPort in XLATE_PORTS:
                            srcPortDesc = "EPH"
                            
                        if "EPH" in dstPortDesc:
                            dstPort = "EPH"
                        else:
                            dstPort = str(dstPort)          
                                
                        if "building automation" in srcPortDesc.lower():
                            srcPortDesc = "BACnet"
                            
                        if "building automation" in dstPortDesc.lower():
                            dstPortDesc = "BACnet"             
                        
                        if alertCC:
                            alert = alertCC
                        elif alertSRCPort:
                            alert = alertSRCPort
                        elif alertDSTPort:
                            alert = alertDSTPort
                        else:
                            alert = ""                    
                        
                        # Add a new IP observation and the hour
                        srcMAC = macData[0]
                        srcMFG = macData[1]
                        dstMAC = macData[2]
                        dstMFG = macData[3]
                        
                        if unknownConnection:
                            alert = unknownConnection
                            
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, srcPort, dstPort, "UDP"), srcIP, dstIP, srcMFG, dstMFG, srcPortDesc, dstPortDesc, icsFlag, countryDetails, when, alert, iso, packetSize)

                            # Post them to PortObject Dictionary
                        if srcPort != "EPH":
                            self.ipOB.AddPortOb((srcIP, srcPort), srcPortDesc, when, iso, icsSrcFlag)
                        if dstPort != "EPH":
                            self.ipOB.AddPortOb((dstIP, dstPort), dstPortDesc, when, iso, icsDstFlag)
                      
                    elif transport == "ICMP":
                        '''
                         0                   1                   2                   3  
                         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                         |      Type     |      Code     |            Checksum           |
                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                         |                                                               |
                         +                          Message Body                         +
                         |                                                               |
                         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                         '''
                        
                        if alertCC:
                            alert = alertCC                        
                        # Add a new IP observation and the hour
                        
                        # Add a new IP observation and the hour
                        srcMAC = macData[0]
                        srcMFG = macData[1]
                        dstMAC = macData[2]
                        dstMFG = macData[3]
                        
                        if unknownConnection:
                            alert = unknownConnection    
    
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, "", "", "ICMP"), srcIP, dstIP, srcMFG, dstMFG, "", "", icsFlag, ['','','','','',''], when, alert, iso, packetSize)
                    
                    else:
                        srcMAC = macData[0]
                        srcMFG = macData[1]
                        dstMAC = macData[2]
                        dstMFG = macData[3]                        
                        alert = "ABNORMAL-TRANSPORT"
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, "", "", transport), srcIP, dstIP, srcMFG, dstMFG, "", "", icsFlag, ['','','','','',''], when, alert, iso, packetSize)
                            
                elif frameType == "ARP":
                    '''
                    0                   1      
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |  Dst-MAC  |  Src-MAC  |TYP|
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |                           |
                    +       Request-Reply       +
                    |                           |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |        PAD        |  CRC  |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     '''
                    if unknownConnection:
                        alert = unknownConnection
                        
                    # Add a new IP observation and the hour
                    self.ipOB.AddOb((fullSrcMAC, fullDstMAC, "", "","ARP"), "", "", "", "", "", "", icsFlag, ['','','','','',''], when, alert, iso, packetSize)                            
                        
                elif frameType == "IPv6":
                    
                    IPv6_LEN = 40      # IPv6 HEADER  LENGTH
                    ETH_LEN  = 14      # ETHERNET HDR LENGTH
                    
                    pktRaw = pkt.raw()
                    packetSizeV6 = len(pktRaw)
                    
                    ipv6Header = pktRaw[ETH_LEN:ETH_LEN+IPv6_LEN]
    
                    ipv6HeaderTuple = struct.unpack('!IHBBQQQQ' , ipv6Header)
                
                    flush = ipv6HeaderTuple[0]
                    pLength = ipv6HeaderTuple[1]
                    nextHdr = ipv6HeaderTuple[2]
                    hopLmt  = ipv6HeaderTuple[3]
                    srcIP   = (ipv6HeaderTuple[4] << 64) | ipv6HeaderTuple[5]
                    dstIP   = (ipv6HeaderTuple[6] << 64) | ipv6HeaderTuple[7]                 
    
                    srcIP = str(netaddr.IPAddress(srcIP))
                    dstIP = str(netaddr.IPAddress(dstIP))    
                    
                    self.macIPDict[(fullSrcMAC, srcIP)] = fldSrcMFG
                    self.macIPDict[(fullDstMAC, dstIP)] = fldDstMFG             
                
                    #srcCC, srcCountryName, srcCategory,  = self.cc.lookup(srcIP)
                    #dstCC, dstCountryName, dstCategory   = self.cc.lookup(dstIP)       
                
                    self.srcCC, self.srcCountryName, self.srcCategory,  = self.cc.lookup(srcIP)
                    self.dstCC, self.dstCountryName, self.dstCategory   = self.cc.lookup(dstIP)
                
                    if self.srcCategory == "HOSTILE" or self.dstCategory == "HOSTILE":
                        alertCC = 'COUNTRY-HOSTILE'
                    else:
                        alertCC = ''
                    
                    if not alertCC:
                        if self.srcCategory == "FOREIGN" or self.dstCategory == "FOREIGN":
                            alertCC = 'COUNTRY-FOREIGN'
                        else:
                            alertCC = ''      
                            
                    if not alertCC:
                        if self.srcCategory == "DANGEROUS" or self.dstCategory == "DANGEROUS":
                            alertCC = 'COUNTRY-DANGEROUS'
                        else:
                            alertCC = ''                          
    
                    countryDetails = [self.srcCC, self.srcCountryName, self.srcCategory, self.dstCC, self.dstCountryName, self.dstCategory]
                
                    translate = self.traOBJ.lookup(str(nextHdr))
                    transProtocol = translate[0]
                    
                    if transProtocol == "IPv6-ICMP":
                        # Add a new IP observation and the hour
                        if alertCC:
                            alert = alertCC
                            
                        # Add a new IP observation and the hour
                        srcMAC = macData[0]
                        srcMFG = macData[1]
                        dstMAC = macData[2]
                        dstMFG = macData[3]
                        
                        if unknownConnection:
                            alert = unknownConnection
                            
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, "", "", "IPv6-ICMP"), srcIP, dstIP, srcMFG, dstMFG, "", "", icsFlag, ['','','','','',''], when, alert, iso, packetSizeV6)
                        
                    if transProtocol == 'TCP':
        
                        stripTCPHeader = pktRaw[ETH_LEN+IPv6_LEN:ETH_LEN+IPv6_LEN+TCP_LEN]
        
                        # unpack the TCP Header to obtain the
                        # source and destination port
        
                        tcpHeaderBuffer = struct.unpack('!HHLLBBHHH' , stripTCPHeader)
        
                        srcPort = tcpHeaderBuffer[0]
                        dstPort = tcpHeaderBuffer[1]
                        
                        # Lookup Port Description, if not found assume Ephemeral 
                        srcPortDesc, alertSRCPort, alertSRCPortDesc = self.portOBJ.lookup(str(srcPort), "TCP")
                                                         
                        if srcPort in XLATE_PORTS:
                            dstPortDesc = "EPH"
                            
                        if "EPH" in srcPortDesc:
                            srcPort = "EPH"
                        else:
                            srcPort = str(srcPort)                                 
                            
                        dstPortDesc, alertDSTPort, alertDSTPortDesc = self.portOBJ.lookup(str(dstPort), "TCP")     
                                
                        if dstPort in XLATE_PORTS:
                            srcPortDesc = "EPH"
                            
                        if "EPH" in dstPortDesc:
                            dstPort = "EPH"
                        else:
                            dstPort = str(dstPort)                                  
    
                        if "building automation" in srcPortDesc.lower():
                            srcPortDesc = "BACnet"
                            
                        if "building automation" in dstPortDesc.lower():
                            dstPortDesc = "BACnet"                           
                    
                        if alertCC:
                            alert = alertCC
                        elif alertSRCPort:
                            alert = alertSRCPort
                        elif alertDSTPort:
                            alert = alertDSTPort
                        else:
                            alert = ""                    
                              
                        # Add a new IP observation and the hour
                        
                        # Add a new IP observation and the hour
                        srcMAC = macData[0]
                        srcMFG = macData[1]
                        dstMAC = macData[2]
                        dstMFG = macData[3]
                        
                        if unknownConnection:
                            alert = unknownConnection
                            
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, srcPort, dstPort, transProtocol), srcIP, dstIP, srcMFG, dstMFG, srcPortDesc, dstPortDesc, icsFlag, countryDetails, when, alert, iso, packetSizeV6)                      
                        
                        # Post them to PortObject Dictionary
                        if srcPort != "EPH":
                            self.ipOB.AddPortOb((srcIP, srcPort), srcPortDesc, when, iso, icsSrcFlag)
                        if dstPort != "EPH":
                            self.ipOB.AddPortOb((dstIP, dstPort), dstPortDesc, when, iso, icsDstFlag)                            
                        
                    if transProtocol == 'UDP':
        
                        stripUDPHeader = pktRaw[ETH_LEN+IPv6_LEN:ETH_LEN+IPv6_LEN+UDP_LEN]
        
                        # unpack the UDP Header to obtain the
                        # source and destination port
                        udpHeaderBuffer = struct.unpack('!HHHH' , stripUDPHeader)
        
                        srcPort = udpHeaderBuffer[0]
                        dstPort = udpHeaderBuffer[1]
                        
                        # Lookup Port Description, if not found assume Ephemeral 
                        srcPortDesc, alertSRCPort, alertSRCPortDesc = self.portOBJ.lookup(str(srcPort), "UDP")
                        
                        if srcPort in XLATE_PORTS:
                            dstPortDesc = "EPH"                            
                            
                        if "EPH" in srcPortDesc:
                            srcPort = "EPH"
                        else:
                            srcPort = str(srcPort)
    
                        dstPortDesc, alertDSTPort, alertDSTPortDesc = self.portOBJ.lookup(str(dstPort), "UDP") 
    
                        if dstPort in XLATE_PORTS:
                            srcPortDesc = "EPH"     
                            
                        if "EPH" in dstPortDesc:
                            dstPort = "EPH"
                        else:
                            dstPort = str(dstPort)          
                                    
                        if "building automation" in srcPortDesc.lower():
                            srcPortDesc = "BACnet"
                            
                        if "building automation" in dstPortDesc.lower():
                            dstPortDesc = "BACnet"               
                        
                        if alertCC:
                            alert = alertCC
                        elif alertSRCPort:
                            alert = alertSRCPort
                        elif alertDSTPort:
                            alert = alertDSTPort
                        else:
                            alert = ""                    
                                            
                        # Add a new IP observation and the hour
                        
                        # Add a new IP observation and the hour
                        srcMAC = macData[0]
                        srcMFG = macData[1]
                        dstMAC = macData[2]
                        dstMFG = macData[3]
                        
                        if unknownConnection:
                            alert = unknownConnection
                            
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, srcPort, dstPort, "UDP"), srcIP, dstIP, srcMFG, dstMFG, srcPortDesc, dstPortDesc, icsFlag, countryDetails, when, alert, iso, packetSizeV6)

        
                        # Post them to PortObject Dictionary
                        if srcPort != "EPH":
                            self.ipOB.AddPortOb((srcIP, srcPort), srcPortDesc, when, iso, icsSrcFlag)
                        if dstPort != "EPH":
                            self.ipOB.AddPortOb((dstIP, dstPort), dstPortDesc, when, iso, icsDstFlag)
                    
                    else:
                        alert = "ABNORMAL-TRANSPORT"
                        self.ipOB.AddOb((fullSrcMAC, fullDstMAC, "", "", transProtocol), srcIP, dstIP, srcMFG, dstMFG, "", "", icsFlag, ['','','','','',''], when, alert, iso, packetSize)                        
                        
            try:
                icsCapture.close()
                LogEvent("Renaming Processed PCAP File: "+self.targetFile)  
                
                prefix_ts = dt.now().strftime("%Y%m%d_%H%M%S")

                dstFile = "x_"+prefix_ts+"-"+pcap  
                self.dstFile = os.path.join(PCAPDIR, dstFile)
                os.rename(self.targetFile, self.dstFile)
                
                #os.remove(self.targetFile)  
            except Exception as err:
                LogEvent("Prefixing Processed PCAP File Failed: "+str(err)+", "+self.targetFile+", "+dstFile)
                continue            

        #CREATE THE JSON and CSV RESULTS
        
        elapsed = time.time() - pTime
        if DEBUG:
            print("Processing Time: ", elapsed)
        
        self.finalReport = self.ipOB.CreateJSONandCSV(REPORTS)  
                

    def CalcCaptureSize(self):

        fileList = os.listdir(self.targetFolder)
        self.captureSize = 0
        for eachFile in fileList:
            fullPath = os.path.join(self.targetFolder, eachFile)
            self.captureSize += os.path.getsize(fullPath) 

    def TCPDUMP(self):
        
        self.targetFolder = "./PCAP"
        LogEvent("Target Folder:   "+self.targetFolder)
        LogEvent("NIC:             "+self.NIC)
        LogEvent("\n")

        nic = self.NIC
        
        MIN_RUN = ''        
            
        while True:   #SENSOR RUNS FOREVER
            
            minute = dt.now().minute
            MIN_RUN = str(self.INTERVAL)         
            
            self.pcapFile = "./PCAP/current.pcap"
            cmd = "timeout " + MIN_RUN + " tcpdump -n -i " +nic+ " -Z root -C 40 -w " + self.pcapFile
            LogEvent("TCPDUMP Start")
            
            try:
                self.p = Popen(cmd, 
                               shell=True,
                               stdout=PIPE, 
                               stderr=PIPE, 
                               universal_newlines=True )
                
            except Exception as err:         
                LogEvent("TCPDUMP Exception: "+ str(err))
                if DEBUG:
                    print(str(err))
            
            time.sleep(2)

            while True: 
                stat = self.p.poll() 
                if stat == None:                                      
                    time.sleep(5)
                else:
                    break
                
            self.p.kill()
            
            time.sleep(2)
                        
            self.CalcCaptureSize() 
            LogEvent("Capture Completed Total Capture Size: "+'{:,}'.format(self.captureSize)+" Bytes")   
            
            LogEvent("Start Processing PCAP")            
            self.ProcessPCAP()
            LogEvent("End Processing PCAP")
                            

def ValidateFile(theFile):
    
    ''' Validate the theFile exists and is readable '''
    # Validate the path is a directory
    print(os.path.curdir)
    if not os.path.isfile(theFile):
        raise argparse.ArgumentTypeError('File does not exist')

    # Validate the path is writable
    if os.access(theFile, os.R_OK):
        return theFile
    else:
        raise argparse.ArgumentTypeError('Files is not readable')
    
def ParseCommandLine():
    
    ''' Parse the Command line and return the arguments collected '''
    
    parser = argparse.ArgumentParser(description='A Python script for passive network sensing')
    group = parser.add_mutually_exclusive_group()

    group.add_argument('-n',  '--nic',      help="Optional Select passive capture NIC")
    group.add_argument('-p',  '--pcapFile', action="store_true",  help="Optional Process pcap files found in ./PCAP Folder")
    
    parser.add_argument('-k',  '--knownConn', required=True, type= ValidateFile,  help="Path to Known-Connections-pickle")                 
    parser.add_argument('-c',  '--interval',  default=60, type=int, help="Capture Interval in Minutes")   

    theArgs = parser.parse_args()           

    return theArgs


# End Parse Command Line ===========================


def main():

    args = ParseCommandLine()
    
    if DEBUG:
        print("NIC: ", args.nic)
        print("KNOWN-CONNECTIONS-FILE: ", args.knownConn)
        print("INTERVAL: "+str(args.interval))
        print(args.pcapFile)
    
    InitLog()
    runObj = StartUp(args.nic, args.pcapFile, args.knownConn, args.interval*60)
    
    if  args.nic:
        runObj.TCPDUMP()  # Run Forever
    elif args.pcapFile:
        runObj.ProcessPCAP()
        print("PCAP Processed")
        print("Script End")

# Main Script Starts Here

if __name__ == '__main__':
    # Start a TCP health listener for the sensor software (default 9101)
    try:
        from health_endpoint import start_tcp_listener, start_http_status
    except Exception:
        from .health_endpoint import start_tcp_listener, start_http_status

    hp = int(os.environ.get('HEALTH_PORT', '9101'))
    ht = os.environ.get('HEALTH_TYPE', 'tcp')
    if ht.lower() == 'http':
        start_http_status(hp, path=os.environ.get('HEALTH_PATH', '/status'), name='sensor-software')
    else:
        start_tcp_listener(hp, name='sensor-software')

    main()



