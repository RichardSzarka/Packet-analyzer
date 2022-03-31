

class EthernetII:
    def __init__(self, whole, number, destinationMac, sourceMac, etherType, length, mediumLength, **kwargs):
        self.Whole = whole
        self.Number = number
        self.length = length
        self.MediumLength = mediumLength

        self.Layer2 = { "destinationMac": destinationMac, "sourceMac": sourceMac, "etherType": etherType}
        self.Layer3 = {}
        self.Layer4 = {}

        for key, value in kwargs.items():   # for cyklus ktorý priradí do správnych vrstiev jednotlivé klučove argumenty
            # podla názvu klúča
            if "L2" in key:
                self.Layer2[key] = value

            if "L3" in key:
                self.Layer3[key] = value

            if "L4" in key:
                self.Layer4[key] = value



class IEEE_NovellRaw:
    def __init__(self, Whole, Number, destinationMac, sourceMac, lenght, pcapilength, MediumLength, IPXheader, Data):
        self.Whole = Whole
        self.Number = Number
        self.MediumLength = MediumLength
        self.PCAPIlength = pcapilength
        self.Data = Data

        class Layer2:
            def __init__(self, sourceMac, destinationMac, lenght, IPXheader):
                self.DestinationMac = destinationMac
                self.SourceMac = sourceMac
                self.Lenght = lenght
                self.IPXheader = IPXheader

        self.layer2 = Layer2(sourceMac, destinationMac, lenght, IPXheader)

class IEEE_802_LLC:
    def __init__(self, Whole, Number, destinationMac, sourceMac, lenght, pcapilength, mediumLength, DSAP, SSAP, control, data):
        self.Whole = Whole
        self.Number = Number
        self.MediumLength = mediumLength
        self.PCAPIlength = pcapilength
        self.Data = data

        class Layer2:
            def __init__(self, sourceMac, destinationMac, lenght, DSAP, SSAP, control):
                self.DestinationMac = destinationMac
                self.SourceMac = sourceMac
                self.lenght = lenght
                self.DSAP = DSAP
                self.SSAP = SSAP
                self.Control = control

        self.layer2 = Layer2(sourceMac, destinationMac, lenght, DSAP, SSAP, control)


class IEEE_802_LLC_SNAP:
    def __init__(self, Whole, Number, destinationMac, sourceMac, length, pcapilength, mediumLength, DSAP, SSAP, control, vendorCode,
                 etherType, data):
        self.Whole = Whole
        self.Number = Number
        self.MediumLength = mediumLength
        self.PCAPIlength = pcapilength
        self.Data = data

        class Layer2:
            def __init__(self, sourceMac, destinationMac, length, DSAP, SSAP, control, vendorCode, etherType):
                self.DestinationMac = destinationMac
                self.SourceMac = sourceMac
                self.Lenght = length
                self.DSAP = DSAP
                self.SSAP = SSAP
                self.Control = control
                self.VendorCode = vendorCode
                self.EtherType = etherType

        self.layer2 = Layer2(sourceMac, destinationMac, length, DSAP, SSAP, control, vendorCode, etherType)

