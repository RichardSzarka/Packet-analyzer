from classes import *


# funkcia ktorá správne spracuje EthernetII IPv4 typy
def handle_ETH_IPv4(frame, Number, destinationMac, sourceMac, EtherType, EtherLength):
    Header_length = frame[29]  # dĺžka IP vrstvy (keby je opional padding)
    transP = frame[46:48]  # transportný protokol použitý

    # ak je to UDP alebo TCP tak vypočítaj počiatočnú pozíciu zdrojových a cielových portov
    if transP == "06" or transP == "11":
        sourcePort = frame[(int(Header_length) * 8 + 28):(int(Header_length) * 8 + 32)]
        destinationPort = frame[(int(Header_length) * 8 + 32):(int(Header_length) * 8 + 36)]
        if transP == "06":
            h_length = frame[(int(Header_length) * 8 + 52):(int(Header_length) * 8 + 53)]
            flags = frame[(int(Header_length) * 8 + 54):(int(Header_length) * 8 + 56)]
            return EthernetII(frame, Number, destinationMac, sourceMac, EtherType, len(frame) / 2, EtherLength + 4,
                              L3header_length=Header_length, L3sourceIp=frame[52:60], L3destinationIp=frame[60:68],
                              L3transP=frame[46:48], L4sourcePort=sourcePort, L4destinationPort=destinationPort,
                              L4flags=flags, L4header=h_length)
        else:
            return EthernetII(frame, Number, destinationMac, sourceMac, EtherType, len(frame) / 2, EtherLength + 4,
                              L3header_length=Header_length, L3sourceIp=frame[52:60], L3destinationIp=frame[60:68],
                              L3transP=frame[46:48], L4sourcePort=sourcePort, L4destinationPort=destinationPort)
    # ak to je ICMP
    if transP == "01":
        return EthernetII(frame, Number, destinationMac, sourceMac, EtherType, len(frame) / 2, EtherLength + 4,
                          L3header_length=Header_length, L3sourceIp=frame[52:60], L3destinationIp=frame[60:68],
                          L3transP=frame[46:48], L4message=frame[68:70], L4code=frame[70:72])

    # ak to je iné
    else:
        return EthernetII(frame, Number, destinationMac, sourceMac, EtherType, len(frame) / 2, EtherLength + 4,
                          L3header_length=Header_length, L3sourceIp=frame[52:60], L3destinationIp=frame[60:68],
                          L3transP=frame[46:48])


# funkcia ktorá správne spracuje EthernetII IPv6 typ
def handle_ETH_IPv6(frame, Number, destinationMac, sourceMac, EtherType, EtherLength):
    Header_length = "10"
    sourcePort = frame[(int(Header_length) * 8 + 28):(int(Header_length) * 8 + 32)]
    destinationPort = frame[(int(Header_length) * 8 + 32):(int(Header_length) * 8 + 36)]

    return EthernetII(frame, Number, destinationMac, sourceMac, EtherType, len(frame) / 2, EtherLength + 4,
                      L3header_length=Header_length, L3sourceIp=frame[44:76], L3destinationIp=frame[76:108],
                      L3transP=frame[40:42], L4sourcePort=sourcePort, L4destinationPort=destinationPort)
