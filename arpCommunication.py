from printing import *


def checkArpRequest(frame, arp_communication):      # funkcia ktorá správne
    for arp_pair in arp_communication:
        if arp_pair[-1] == 0:   # ak je na konci 0 v páry tak je komunikácia ukončená
            continue
        for packet in arp_pair:     # ak je už rovnaký request v neukončenej komunikácii tak ho k nej priraď
            if (frame.Layer3["L3senderIp"] == packet.Layer3["L3senderIp"] and frame.Layer3["L3targetIp"] ==
                    packet.Layer3["L3targetIp"]) and frame.Layer3["L3senderMac"] == packet.Layer3["L3senderMac"] and \
                    frame.Layer3["L3targetMac"] == packet.Layer3["L3targetMac"]:
                arp_pair.append(frame)
                return 1

    return 0


def checkArpReply(frame, arp_communication):    # funkcia ktorá správne priradí ARP reply ku requestom
    for arp_pair in arp_communication:
        # ak sedia IP adresy na Reply
        if (frame.Layer3["L3senderIp"] == arp_pair[0].Layer3["L3targetIp"] and frame.Layer3["L3targetIp"] ==
                arp_pair[0].Layer3["L3senderIp"]) and frame.Layer3["L3targetMac"] == arp_pair[0].Layer3["L3senderMac"]:
            if arp_pair[-1] != 0:       # ak nie je 0 na konci (indikátor ucelenej komunikácie)
                arp_pair.append(frame)
                arp_pair.append(0)      # pridaj nulu na indikovanie ucelenej komunikácie
                return 1

    return 0


def arpcom(frames):
    arp_frames = []
    arp_communications = []

    for frame in frames:    # ak je to ARP priraď ho do pola kde su ARP protokoly
        if isinstance(frame, EthernetII):
            if "L3opcode" in frame.Layer3:
                arp_frames.append(frame)

    for frame in arp_frames:
        arp_pairs = []
        if frame.Layer3["L3opcode"] == "0001":      # ak je to request pozri či už nebol v minulosti taký istý
            if checkArpRequest(frame, arp_communications):
                continue
            else:   # ak nie vytvor nový pár
                arp_pairs.append(frame)
                arp_communications.append(arp_pairs)
        else:
            if checkArpReply(frame, arp_communications):   # ak je to reply pozri či už nebol v minulosti k nemu request
                continue
            else:   # ak nie vytvor pár len s jedným reply
                arp_pairs.append(frame)
                arp_pairs.append(0)
                arp_communications.append(arp_pairs)

    comm = 0
    for arp in arp_communications:
        if arp[-1] == 0 and len(arp) > 2:   # ak to obsahovalo aspon 2 ARP protokoly a bola 0 na konci
            comm += 1
            print("--------------------------------{}-----------------------------\n".format(comm))
            print("---------------The communication below was whole set of reqeusts and a reply--------------\n")
            for packet in arp:
                if packet != 0:
                    printPacket(packet, None)
    comm = 0
    for arp in arp_communications:  # všetky ostatné sú neucelené (aj prázdne reply)
        if arp[-1] != 0 or (arp[-1] == 0 and len(arp) <= 2):
            comm += 1
            print("--------------------------------{}-----------------------------\n".format(comm))
            if arp[-1] == 0 and len(arp) <= 2:
                print("---------------The communication below was solo reply--------------")
            else:
                print("---------------The communication below was only request/requests--------------")
            for packet in arp:
                printPacket(packet, None)
