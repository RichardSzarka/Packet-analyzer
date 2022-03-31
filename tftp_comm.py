from printing import *


def tftpcommunication(frames, mode):
    communication = []
    tftpstart = []

    for frame in frames:
        # ak to je EthernetII
        if isinstance(frame, EthernetII) and frame.Layer2["etherType"] == "0800":
            # aj je to UDP
            if frame.Layer3["L3transP"] == "11":
                # ak je destination port 69
                if frame.Layer4["L4destinationPort"] == "0045":
                    # ak je to prvý rámec v komunikácii
                    tftpstart.append(frame)
                    communication.append(tftpstart)
                    tftpstart = []

    # rozdelí ostatné podla 1. rámca
    for comm in communication:
        Port_type = comm[0].Layer4["L4sourcePort"]
        sourceIp = comm[0].Layer3["L3sourceIp"]
        destinationIp = comm[0].Layer3["L3destinationIp"]

        for frame in frames:
            # ak to je EthernetII
            if isinstance(frame, EthernetII) and frame.Layer2["etherType"] == "0800":
                 # aj je to UDP
                if frame.Layer3["L3transP"] == "11":
                    # ak je destination port 69
                    # ak to je iný port zisti či sa zhoduje s rozpracovanou komunikáciou a odignoruje všetky predtým
                    # (keby port bol predtým používaný)
                    if frame == comm[0] or frame.Number < comm[0].Number:
                        continue
                    if (frame.Layer4["L4sourcePort"] == Port_type or frame.Layer4["L4destinationPort"] == Port_type) and \
                        (frame.Layer3["L3sourceIp"] == sourceIp or frame.Layer3["L3sourceIp"] == destinationIp) and \
                        (frame.Layer3["L3destinationIp"] == destinationIp or frame.Layer3["L3destinationIp"] == sourceIp):

                        comm.append(frame)


    array = []
    for comm in communication:
        for frame in comm:
            array.append(frame.Number)
    if mode:
        return array

    cnt = 1
    # výpis
    for comm in communication:
        print("----------------{}---------------".format(cnt))
        cnt += 1
        if len(comm) > 20:
            for i in range(len(comm)):
                if i < 10:
                    printPacket(comm[i], array)
                elif len(comm) - i <= 10:
                    printPacket(comm[i], array)
        else:
            for frame in comm:
                printPacket(frame, array)
