from textedits import *
from classes import *


def printPacket(frame, tftp_frames):  # jednotlivé výpisy
    if isinstance(frame, EthernetII):  # Ak je to objekt EthernetII
        print("Number:", frame.Number)
        print("EthernetII")
        print("Source MAC address", edit(frame.Layer2["sourceMac"], 0))  # Funkcia edit prerába dáta z pracovnej
        #  podoby do podoby na cítanie

        print("Destination MAC address", edit(frame.Layer2["destinationMac"], 0))
        print("EtherType:", edit(frame.Layer2["etherType"], 0))
        print("Frame length on PCAP API: {}B".format(int(frame.length)))
        print("Frame length on medium: {}B".format(int(frame.MediumLength)))
        # ak existuje v rozobratom rámci dlžka hlavy (header length) tak je to ho rozoberaj nasledovne
        if "L3header_length" in frame.Layer3:
            #   jedna jedntoka hodnoty header length indukuje 4 Bajty
            print("Header length: {length}B".format(length=4 * int(frame.Layer3["L3header_length"],base=16)))

            #   funkcia edit IP dáta IPv4  a IPv6 do čitatelnejšej podoby z dátovej podoby
            print("Source IP:", editIP(frame.Layer3["L3sourceIp"], frame.Layer2["etherType"]))
            print("Destination IP:", editIP(frame.Layer3["L3destinationIp"], frame.Layer2["etherType"]))

            #   ak je tam transportný protokol (analyzujeme ho) pokračuj nasledovne
            if frame.Layer3["L3transP"] in transmission_protocols:
                print("Transmission protocol:", transmission_protocols[frame.Layer3["L3transP"]])

                #   ak je ten Transportný protocol UDP ale TCP analyzujeme aj 4. vrstvu transportnú
                if transmission_protocols[frame.Layer3["L3transP"]] == "UDP" or transmission_protocols[
                    frame.Layer3["L3transP"]] == "TCP":
                    #   výpis portov
                    print("Source port:", int(frame.Layer4["L4sourcePort"], base=16))
                    print("Destination port:", int(frame.Layer4["L4destinationPort"], base=16))
                    #   funkcia ktorá zistí či to je známi port
                    been_tftp = False
                    if tftp_frames is not None:
                        if frame.Number in tftp_frames:
                            been_tftp = True
                            print("tftp")
                    if not been_tftp:
                        print(getSourcePortType(int(frame.Layer4["L4sourcePort"], base=16),
                                                int(frame.Layer4["L4destinationPort"], base=16),
                                                transmission_protocols[frame.Layer3["L3transP"]]))

                    #   ak to je TCP treba pozrieť aj na flagy
                    if transmission_protocols[frame.Layer3["L3transP"]] == "TCP":
                        #   otočím binárny výpis v stringu flagov aby sa index flagu zhodoval s významom
                        flag = str(bin(int(frame.Layer4["L4flags"], 16)))[2:][::-1]
                        string = ""
                        #   vypíš všetky flagy čo tam su
                        for i in range(len(flag)):
                            if flag[i] == "1":
                                string += flag_types[str(i)] + " "
                        print("Flags: " + string)

                #   ak je to ICMP
                elif transmission_protocols[frame.Layer3["L3transP"]] == "ICMP":
                    if frame.Layer4["L4message"] in ICMPmessages:
                        print("Type of message:", ICMPmessages[frame.Layer4["L4message"]])
                    else:
                        print("Type of message: Unknown port")
        # aj je v sieťovej vrstve Opcode tak je to ARP request alebo reply
        if "L3opcode" in frame.Layer3:
            print("Opcode:", arp_communications[frame.Layer3["L3opcode"]])
            print("Sender IP:", editIP(frame.Layer3["L3senderIp"], "0800"))
            print("Target IP:", editIP(frame.Layer3["L3targetIp"], "0800"))

        # vypíš celý rámec
        print("Whole:\n" + edit(frame.Whole, 1))
        print("\n-------------------------------------------------------------- \n")

    #   výpis IEEE 802 LLC
    elif isinstance(frame, IEEE_802_LLC):
        print("Number:", frame.Number)
        print("IEEE 802.3 LLC")
        print("Source MAC address:", edit(frame.layer2.SourceMac, 0))
        print("Destination MAC address:", edit(frame.layer2.DestinationMac, 0))
        print("Frame length on PCAP API: {}B".format(int(frame.PCAPIlength)))
        print("Frame length on medium: {}B".format(int(frame.MediumLength)))
        print("DSAP:", getLLC(frame.layer2.DSAP))
        print("SSAP:", getLLC(frame.layer2.SSAP))
        print("Whole:\n" + edit(frame.Whole, 1))
        print("\n --------------------------------------------------------------\n")
    #   výpis IEEE RAW
    elif isinstance(frame, IEEE_NovellRaw):
        print("Number:", frame.Number)
        print("IEEE Novell Raw")
        print("Source MAC address:", edit(frame.layer2.SourceMac, 0))
        print("Destination MAC address:", edit(frame.layer2.DestinationMac, 0))
        print("Frame length on PCAP API: {}B".format(int(frame.PCAPIlength)))
        print("Frame length on medium: {}B".format(int(frame.MediumLength)))
        print("Protocol: IPX")
        print("Whole:\n" + edit(frame.Whole, 1))
        print("\n --------------------------------------------------------------\n")
    #   výpis IEE SNAP
    elif isinstance(frame, IEEE_802_LLC_SNAP):
        print("Number:", frame.Number)
        print("IEEE 802.3 LLC SNAP")
        print("Source MAC address:", edit(frame.layer2.SourceMac, 0))
        print("Destination MAC address:", edit(frame.layer2.DestinationMac, 0))
        print("Frame length on PCAP API: {}B".format(int(frame.PCAPIlength)))
        print("Frame length on medium: {}B".format(int(frame.MediumLength)))
        print("EtherType:", getEther(frame.layer2.EtherType))
        print("Whole:\n" + edit(frame.Whole, 1))
        print("\n --------------------------------------------------------------\n")


def getSourcePortType(sourcePort, destinationPort, transP):
    destinationPort = str(destinationPort)
    sourcePort = str(sourcePort)

    #   vráť typ "známeh" portu pre TCP alebo UDP protocoly
    if transP == "UDP":
        if sourcePort in udpPorts:
            return udpPorts[sourcePort]
        elif destinationPort in udpPorts:
            return udpPorts[destinationPort]
        else:
            return "not known port"
    else:
        if sourcePort in tcpPorts:
            return tcpPorts[sourcePort]
        elif destinationPort in tcpPorts:
            return tcpPorts[destinationPort]
        else:
            return "not known port"
