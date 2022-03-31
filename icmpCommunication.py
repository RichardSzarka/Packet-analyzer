from printing import *

#trace-6 trace-26
def check_pairs(frame, paired_comm):
    for pairs in paired_comm:   # ak do nej patrí prirad a vrat 1
        if pairs[0].Layer3["L3sourceIp"] == frame.Layer3["L3sourceIp"] and pairs[0].Layer3["L3destinationIp"] == \
                frame.Layer3["L3destinationIp"] or \
                pairs[0].Layer3["L3destinationIp"] == frame.Layer3["L3sourceIp"] and pairs[0].Layer3["L3sourceIp"] == \
                frame.Layer3["L3destinationIp"]:
            pairs.append(frame)
            return 1

    return 0    # ak do nej nepatri vrat 0


def icmpCom(frames):
    array = []
    for frame in frames:    # vytrieď si leen ICMP rámce
        if isinstance(frame, EthernetII):
            if frame.Layer2["etherType"] == "0800":
                if frame.Layer3["L3transP"] == "01":
                    array.append(frame)

    paired_comm = []
    pair = []
    for frame in array:     #  rozdel do jednotlivých komunikácii
        if check_pairs(frame, paired_comm):     # je už v nejakej komunikácii?
            continue
        else:   # ak nie vytvor novu
            pair.append(frame)
            paired_comm.append(pair)
            pair = []

    cnt = 0
    for pair in paired_comm:    # výpis
        cnt += 1
        print("---------------------{}-----------------".format(cnt))
        if len(pair) > 20:  # zisti či je ich viac ako 20
            for i in range(len(pair)):
                if i < 10:
                    printPacket(pair[i], None)
                elif len(pair) - i <= 10:
                    printPacket(pair[i], None)

        else:
            for frame in pair:
                printPacket(frame, None)
