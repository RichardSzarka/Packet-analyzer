from printing import *

def isframeused(frame, grouped_frames):
    for frames in grouped_frames:  # zisťuje či rámec je v nejakom zoskupení rámcov
        if frame in frames:
            return True

    return False

# funkcia na združenie jednotlivých rámcov TCP komunikácií
def groupUpFrames(type_frames):
    grouped_frames = []
    for frame1 in type_frames:  # for cyklus ktorý prechádza postupne všetky rámce

        if isframeused(frame1, grouped_frames): # zisťuje či rámec je v nejakom zoskupení rámcov
            continue
        # ak nie je treba vytvoriť novú skupinu rámcov a nájsť k nemu príslušné rámce
        frame1sourcePort = frame1.Layer4["L4sourcePort"]
        frame1destinationPort = frame1.Layer4["L4destinationPort"]
        frame1sourceIp = frame1.Layer3["L3sourceIp"]
        frame1destinationIp = frame1.Layer3["L3destinationIp"]
        newGroup = []
        newGroup.append(frame1)

        for frame2 in type_frames:
            # ak sa porovnávaju 2 tie isté framy tak preskoč cyklus
            if frame1 == frame2:
                continue

            frame2sourcePort = frame2.Layer4["L4sourcePort"]
            frame2destinationPort = frame2.Layer4["L4destinationPort"]
            frame2sourceIp = frame2.Layer3["L3sourceIp"]
            frame2destinationIp = frame2.Layer3["L3destinationIp"]

            # ak sa zhoduju IP adresy alebo su vymenené a to isté s portami tak ho pridaj do jednej komunikácie
            if (frame1sourceIp == frame2sourceIp and frame1destinationIp == frame2destinationIp) or \
                    (frame1sourceIp == frame2destinationIp and frame1destinationIp == frame2sourceIp):

                if (frame1sourcePort == frame2sourcePort and frame1destinationPort == frame2destinationPort) or \
                        (frame1sourcePort == frame2destinationPort and frame1destinationPort == frame2sourcePort):

                    newGroup.append(frame2)

        grouped_frames.append(newGroup)
    return grouped_frames


#   TODO prirobyť aj 3 ukončovací handshake (mám len 4)
def findWholeCommunication(grouped_frames):
    finished = []
    started = []

    communicationStarted = False
    communicationFinished = False
    # 3/4-way handshake na zacatie komunkácie
    syn1_check = True
    syn2_check = True
    ack1_start = True
    ack2_start = True
    # 3/4-way handshake na ukoncenie komunikácie
    fin1_check = True
    ack_end1 = True
    fin2_check = True
    ack_end2 = True

    reset_check = True

    for frames in grouped_frames:
        for frame in frames:
            flags = str(bin(int(frame.Layer4["L4flags"], 16)))[2:][::-1] # reversnuty string z flagov
            length = len(flags)
            # ak sa este nenašiel prvý SYN tak pozri či rámec ho nemá
            if (syn1_check) and length > 1 and flags[1] == "1":
                syn1_check = False
                # nastav hladané porty na porty tohto ramca
                sourcePort = frame.Layer4["L4sourcePort"]
                destinationPort = frame.Layer4["L4destinationPort"]
                continue

            # ak sa už našiel prvý SYN a hladá sa SYN ACK
            elif ack1_start and (not syn1_check) and length > 4 and flags[4] == "1" and \
                    sourcePort == frame.Layer4["L4destinationPort"] and destinationPort == frame.Layer4["L4sourcePort"]:
                ack1_start = False
                if syn2_check and flags[1] == "1":
                    syn2_check = False
                continue

            # ak by to bol 4 way handshake
            elif (not ack1_start) and syn2_check and length > 1 and flags[1] == "1" and \
                    sourcePort == frame.Layer4["L4destinationPort"] and destinationPort == frame.Layer4["L4sourcePort"]:
                syn2_check = False
                continue

            # ak sa uť našiel SYN ACK a hladá sa ACK
            elif (not syn2_check) and ack2_start and length > 4 and flags[4] == "1" and \
                    sourcePort == frame.Layer4["L4sourcePort"] and destinationPort == frame.Layer4["L4destinationPort"]:
                ack2_start = False
                communicationStarted = True

            # Ak prišiel RST
            elif communicationStarted and reset_check and length > 2 and flags[2] == "1":
                reset_check = False
                communicationFinished = True
                continue

            # Ak prišiel FIN
            elif communicationStarted and fin1_check and flags[0] == "1":
                fin1_check = False
                sourcePort = frame.Layer4["L4sourcePort"]
                destinationPort = frame.Layer4["L4destinationPort"]
                continue

            # Ak prišiel 1. FIN a hladá sa ACK z 2. Uzla
            elif (not fin1_check) and ack_end1 and length > 4 and flags[4] == "1" and \
                    sourcePort == frame.Layer4["L4destinationPort"] and destinationPort == frame.Layer4["L4sourcePort"]:
                ack_end1 = False
                if fin2_check and flags[0] == "1":   # ak by to bol 3-way handshake
                    fin2_check = False
                continue

            # Ak sa našiel ACK druheho uzla a hladá sa FIN 2. uzla
            elif (not ack_end1) and fin2_check and flags[0] == "1" and \
                    sourcePort == frame.Layer4["L4destinationPort"] and destinationPort == frame.Layer4["L4sourcePort"]:
                fin2_check = False
                continue

            # Ak sa našiel FIN 2. uzla a hladá sa ACK 1. uzla
            elif (not fin2_check) and ack_end2 and length > 4 and flags[4] == "1" and \
                    sourcePort == frame.Layer4["L4sourcePort"] and destinationPort == frame.Layer4["L4destinationPort"]:
                fin2_check = False
                communicationFinished = True

        # zisti aká bola predosla komunikácia
        if communicationStarted and communicationFinished:
            finished.append(frames)
        elif communicationFinished and not reset_check:
            finished.append(frames)
        elif communicationStarted and not communicationFinished:
            started.append(frames)

        # nastav flagy na povodnu hodnotu
        communicationStarted = False
        communicationFinished = False

        syn1_check = True
        syn2_check = True
        ack2_start = True

        fin1_check = True
        ack_end1 = True
        fin2_check = True
        ack_end2 = True

        reset_check = True

    return finished, started


def completeComunication(frames, type):
    type_frames = []
    # vytried rámce len na tie ktoré sú EthernetII IPv4, TCP a jeden port sedí s hladanou komunikáciou
    for frame in frames:
        if isinstance(frame, EthernetII) and frame.Layer2["etherType"] == "0800":
            if frame.Layer3["L3transP"] == "06":
                if int(frame.Layer4["L4sourcePort"], base=16) == type or int(frame.Layer4["L4destinationPort"],
                                                                             base=16) == type:
                    type_frames.append(frame)

    # združ jednotlivé komunikácie
    grouped_frames = groupUpFrames(type_frames)

    # zisti ucelené a neucelené komunikácie
    wholeCommunications, startedCommunications = findWholeCommunication(grouped_frames)

    # vypíš jednotlivé ucelené a neucelené komunikácie
    print("\n-------------Whole------------\n")
    if len(wholeCommunications) > 0:
        if len(wholeCommunications[0]) > 20:
            for i in range(len(wholeCommunications[0])):   # ak je ich viac ako 20
                if i < 10:
                    printPacket(wholeCommunications[0][i], None)
                elif len(wholeCommunications[0]) - i <= 10:
                    printPacket(wholeCommunications[0][i], None)
        else:
            for frame in wholeCommunications[0]:
                printPacket(frame, None)

    else:
        print("None")
    print("\n-------------Unfinished------------\n")

    if len(startedCommunications) > 0:
        if len(startedCommunications[0]) > 20:  # ak je ich viac ako 20
            for i in range(len(startedCommunications[0])):
                if i < 10:
                    printPacket(startedCommunications[0][i], None)
                elif len(startedCommunications[0]) - i <= 10:
                    printPacket(startedCommunications[0][i], None)
        else:
            for frame in startedCommunications[0]:
                printPacket(frame, None)
    else:
        print("None")
    print("\n\n")
