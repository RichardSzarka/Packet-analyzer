import sys

from scapy.all import rdpcap
import binascii

import printing
from analyzation import *
from completeComunication import *
from tftp_comm import *
from arpCommunication import *
from icmpCommunication import *

# Meno: Richard
# Priezvisko: Szarka
# Predmet: PKS
# Projekt: 1.
# Semester: 3.
# Cvičiaci: Kristián Košťál

# precitanie frame-ov z pcap suboru
print(
"##############################################\n"
"#.......$$$$$$$\  $$\   $$\  $$$$$$\  .......#\n"
"#.......$$  __$$\ $$ | $$  |$$  __$$\........#\n"
"#.......$$ |  $$ |$$ |$$  / $$ /  \__|.......#\n"
"#.......$$$$$$$  |$$$$$  /  \$$$$$$\.........#\n"
"#.......$$  ____/ $$  $$<    \____$$\........#\n"
"#.......$$ |      $$ |\$$\  $$\   $$ |.......#\n"
"#.......$$ |      $$ | \$$\ \$$$$$$  |.......#\n"
"#.......\__|      \__|  \__| \______/ .......#\n"
"##############################################\n"
)

loaded_file = True

file_was_opened = False

def redirectOutput(answer, file):   # funkcia na presmerovanie vystupu z konzoly do suboru - ak je vystup moc dlhy
    if answer == "1":
        sys.stdout = file


def normalOutput(answer):       # ak je presmerovanie zapnute tak presmeruj spať vystup na konzolu
    if answer == "1":
        sys.stdout = sys.__stdout__


while True:
    if loaded_file:
        subor = input(
            "Which pcap file do you want to open? (pcap file needs to be in the same directory as this program - format: filename)\n")

        try:        # skus ci taky subor existuje
            data = rdpcap(subor)
        except:     # ak nie zopakuj proces nacitania
            print("File not found")
            continue

        reading_toggle = input("Do you want the output to be written into a file? [1/0]\n") # spytaj sa uzivatela ci chce nacitat

        if not (reading_toggle == "0" or reading_toggle == "1"):      # ak nezadal spravny vstup tak zopakuj nacitavanie
            print("Output setup not correct")
            continue

        if reading_toggle == "1":      # ak chce zapisovat do suboru otvor subor
            if file_was_opened:
                file = open("output.txt", "a")
            else:
                file = open("output.txt", "w")
                file_was_opened = True

        else:
            file = None

        # pole na rozobraté (z analyzované frame-y)
        frames = []

        # funkcia na analýzu frame-ov
        counter = 0
        # prechádzanie frame-ov v načítaných datách

        for frame in data:
            # pretvorenie výpisu bytového poľa do hexa. a pretypovanie na string, orezanie prvých dvoch a posledného znaku,
            # následná analýza a pridelenie do poľa spracovaných frame-ov
            frames.append(Analyze(str(binascii.hexlify(bytearray(frame.original)))[2:-1], counter + 1))
            # výpis spracovaného frame-u
            counter += 1

        loaded_file = False
        tftp_frames = tftpcommunication(frames, True)
    # výpis prepínačov pre užívateľa
    answer = input(
                   "\n"+subor+"\t"+"stdout to output.txt: "+reading_toggle+"\n"
                   "\nWhat would you like to see?\n"
                   "1) All\n"
                   "2) HTTP\n"
                   "3) HTTPS\n"
                   "4) TELNET\n"
                   "5) SSH\n"
                   "6) FTP control\n"
                   "7) FTP data\n"
                   "8) TFTP\n"
                   "9) ICMP\n"
                   "10) ARP\n"
                   "11) DNS (seminar implementation)\n"
                   "change) Change source pcap file\n"
                   "toggle) Toogle writing in output.txt\n"
                   "end) End program\n")

    if answer == "1":  # výpis všetkých rámcov
        redirectOutput(reading_toggle, file)

        for frame in frames:
            printPacket(frame, tftp_frames)

        # zisťovanie najfrekventovanejšieho odosielajuceho uzla
        ipv4s = []
        for frame in frames:  # vyizolovanie rámcov obsahujúcich IPv4
            if isinstance(frame, EthernetII) and frame.Layer2["etherType"] == "0800":
                ipv4s.append(frame.Layer3["L3sourceIp"])

        counter = 0
        uniq_ip = [0]
        for ip in ipv4s:  # cyklus zisťujúci najfrekventovanejšiu IP zdrojovú IP adresu
            if ip not in uniq_ip:
                frequency = ipv4s.count(ip)
                uniq_ip.append(ip)  # pole unikátnych IP adries
                uniq_ip[0] += 1
                if frequency > counter: # ak našiel novú frekventovanejšiu IP
                    counter = frequency
                    freqIP = ip
                frequency = 0
                print("{number}. IPv4: {ip}".format(number=uniq_ip[0], ip=editIP(ip, "0800")))

        print("Most frequent ip:", editIP(freqIP, "0800")) # výpis
        print("Number of sendings:", counter)

        normalOutput(reading_toggle)
    elif answer == "2":  # výis kompletných a nekompletných komunikácií v htttp
        redirectOutput(reading_toggle, file)

        completeComunication(frames, 80)

        normalOutput(reading_toggle)
    elif answer == "3":  # výis kompletných a nekompletných komunikácií v htttps
        redirectOutput(reading_toggle, file)

        completeComunication(frames, 443)

        normalOutput(reading_toggle)
    elif answer == "4":  # výis kompletných a nekompletných komunikácií v telnet
        redirectOutput(reading_toggle, file)

        completeComunication(frames, 23)

        normalOutput(reading_toggle)
    elif answer == "5":  # výis kompletných a nekompletných komunikácií v ssh
        redirectOutput(reading_toggle, file)

        completeComunication(frames, 22)

        normalOutput(reading_toggle)
    elif answer == "6":  # výis kompletných a nekompletných komunikácií v ftp - riadiace
        redirectOutput(reading_toggle, file)

        completeComunication(frames, 21)

        normalOutput(reading_toggle)
    elif answer == "7":  # výis kompletných a nekompletných komunikácií v ftp - datove
        redirectOutput(reading_toggle, file)

        completeComunication(frames, 20)

        normalOutput(reading_toggle)
    elif answer == "8":  # výis komunikácií tftp
        redirectOutput(reading_toggle, file)

        tftpcommunication(frames, False)

        normalOutput(reading_toggle)
    elif answer == "9":  # výpis icmp komunikácií
        redirectOutput(reading_toggle, file)

        icmpCom(frames)

        normalOutput(reading_toggle)
    elif answer == "10":  # výis kompletných a nekompletných arp komunikácií - "dvojíc"
        redirectOutput(reading_toggle, file)
        arpcom(frames)
        normalOutput(reading_toggle)

    elif answer == "11":  # doimplementácia
        redirectOutput(reading_toggle, file)
        count = 0
        for frame in frames:
            if isinstance(frame, EthernetII):
                if frame.Layer2["etherType"] == "0800":
                    if frame.Layer3["L3transP"] == "11":
                        if int(frame.Layer4["L4sourcePort"], 16) == 53 or int(frame.Layer4["L4destinationPort"], 16) == 53:
                            count += 1
                            printPacket(frame, None)

        print("Number of DNS frames:", count)
        normalOutput(reading_toggle)

    elif answer == "change":  # boolean indikujúci potrebu načítania nového súbora
        loaded_file = True

    elif answer == "toggle":
        if reading_toggle == "1":
            reading_toggle = "0"
            file.close()
        else:
            reading_toggle = "1"
            if not file_was_opened:
                file_was_opened = "1"
                file = open("output.txt", "w")
            else:
                redirectOutput(file, answer)
                file = open("output.txt", "a")



    elif answer == "end":  # ukončenie programu
        if reading_toggle == "1":  # ak bol subor otvoreny zatvor ho
            file.close()

        break
