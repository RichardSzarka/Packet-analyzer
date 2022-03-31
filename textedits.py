arp_communications = {  # slovník na arp komunikácie
    "0001": "Request",
    "0002": "Reply"
}


def openFile(file, dictionary):  # funkcia na otváranie suborov txt s protocolmi a portmi a iné
    with open(file) as file:
        lines = file.readlines()
        for i in lines:
            line = i.split("=")
            dictionary[line[0]] = line[1][0:-1]


flag_types = {}
EtherTypes = {}
ICMPmessages = {}
LLC_SAPs = {}
transmission_protocols = {}
tcpPorts = {}
udpPorts = {}

openFile("values/flags.txt", flag_types)
openFile("values/EtherType_Values.txt", EtherTypes)
openFile("values/ICMP_messages.txt", ICMPmessages)
openFile("values/LLC_SAP.txt", LLC_SAPs)
openFile("values/transmission_protocols.txt", transmission_protocols)
openFile("values/TCPports.txt", tcpPorts)
openFile("values/UDPports.txt", udpPorts)


def getEther(ether):    # funkcia na ziskanie etherType
    for key in EtherTypes:
        if key == ether:
            return EtherTypes[key]


def getLLC(protocol):    # funkcia na ziskanie LLC protokolu
    for key in LLC_SAPs:
        if key == protocol:
            return LLC_SAPs[key]


def edit(text, data):  # funkcia ktorá zmení data na výpis
    if text in EtherTypes:
        return EtherTypes[text]

    new_text = ""
    for i in range(len(text)):
        ascii_value = ord(text[i])
        if 97 <= ascii_value <= 122:  # male písmená na veľké
            new_text += chr(ascii_value - 32)
        else:
            new_text += text[i]

        # medzery a \n na správnych miestach

        if i % 2 != 0:
            new_text += " "
        if i % 16 == 15 and data == 1:
            new_text += "  "
        if i % 32 == 31 and data == 1:
            new_text += "\n"
    return new_text


def editIP(ip, version):  # funkcia na čitateľnejší výpis IP adries
    output = ""
    if version == "0800":
        for i in range(4):
            sum = int(ip[i * 2:(i * 2 + 2)], base=16)
            output += str(sum) + "."

    elif version == "86dd":
        for i in range(8):
            output += ip[i * 4:(i * 4 + 4)] + ":"

    return output[0:-1]
