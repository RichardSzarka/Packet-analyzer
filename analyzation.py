from eth2handlers import *

def Analyze(frame, Number):
    destinationMac = str(frame[0:12])  # zdrojová mac adresa
    sourceMac = str(frame[12:24])  # zdrojová mac adresa
    EtherType = str(frame[24:28])  # EtherType (ipv4, ipv6, arp) -> môže byť aj dĺžka

    if int(EtherType, base=16) > 1536:  # ak je hodnota EtherType viac ako 1536 jedná sa o EtherType a nie o dĺžku
        EtherLength = len(frame) / 2  # dĺžka frame-u

        if EtherLength < 60:  # ak je EtherLength menší ako 60 tak tam nastalo nejaké zarovnanie
            EtherLength = 60  # , ktoré pcap subor už neposkituje


        if EtherType == "0800":  # ak je EtherType 0800 je to IPv4
            return handle_ETH_IPv4(frame, Number, destinationMac, sourceMac, EtherType, EtherLength)

        # TODO v niektorých protokoloch layer 4 nie su na 1.miestach porty (icmp)

        elif EtherType == "86dd":  # ak je EtherType 86DD je to IPv6
            return handle_ETH_IPv6(frame, Number, destinationMac, sourceMac, EtherType, EtherLength)

        elif EtherType == "0806": # ak je to Arp
            return EthernetII(frame, Number, destinationMac, sourceMac, EtherType, len(frame)/2, EtherLength + 4,
                              L3protocol=frame[32:36],
                              L3opcode=frame[40:44], L3senderMac=frame[44:56], L3senderIp=frame[56:64],
                              L3targetMac=frame[64:76], L3targetIp=frame[76:84])

        else:
            return EthernetII(frame, Number, destinationMac, sourceMac, EtherType, len(frame) / 2, EtherLength + 4)

    else:
        lenght = EtherType  # ak je Ethertype menší ako 1536 je to dĺžka
        PCAPIlength = len(frame) / 2  # dĺžka PCAPI lebo mohol nastať padding

        if PCAPIlength <= 60:
            medium_length = 64

        else:
            medium_length = PCAPIlength + 4

        if frame[28:30] == "ff":  # ak na mieste kde má byť IXP header nájdeme hodnotu FFFF je to typ RAW
            return IEEE_NovellRaw(frame, Number, destinationMac, sourceMac, lenght, PCAPIlength, medium_length,
                                  frame[28:34], frame[34:])

        elif frame[28:30] == "aa":  # ak na mieste kde už sú data nájdeme AAAA je to SNAP
            return IEEE_802_LLC_SNAP(frame, Number, destinationMac, sourceMac, lenght, PCAPIlength, medium_length,
                                     frame[28:30],
                                     frame[30:32], frame[32:34], frame[34:40], frame[40:44], frame[44:])

        else:  # ináč to je LLC
            return IEEE_802_LLC(frame, Number, destinationMac, sourceMac, lenght, PCAPIlength, medium_length,
                                frame[28:30],
                                frame[30:32], frame[32:34], frame[34:])
