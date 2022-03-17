from scapy.all import RadioTap, Dot11ProbeReq, Dot11, Dot11Elt, Dot11FCS, \
     Dot11EltHTCapabilities, Dot11EltVendorSpecific, RadioTapExtendedPresenceMask, sendp, sr1
import time
import datetime

class nintendo_switch_probe_request:
    def __init__(self, intf="wlan0", source='00:00:00:00:00:00', ssid=None):
        self.intf = intf
        self.intfmon = intf + 'mon'
        self.ssid = ssid
        self.source = source
        self.rates = '\x02\x04\x0b\x16'
        self.extrates = '\x0c\x12\x18\x24\x36\x48\x60\x6c'
        self.extcapabilities = "\x04\x00\x00\x00\x00\x00\x00\x40"

    def ProbeReq(self, count=4, ssid=None, dst='ff:ff:ff:ff:ff:ff', fc=0):
        
        if self.ssid is not None:
            ssid = self.ssid
        elif ssid is None:
            ssid = ''

        ext1 = RadioTapExtendedPresenceMask(present='b5+b11+b29+Ext')
        ext2 = RadioTapExtendedPresenceMask(index = 1, present=0x00000820)

        radio = RadioTap(\
            present = 'TSFT+Flags+Rate+Channel+dBm_AntSignal+RXFlags+timestamp+RadiotapNS+Ext', \
            Ext=[ext1, ext2], \
            Rate=1.0,  \
            dBm_AntSignal=-31, \
            Flags='FCS', \
            ChannelFlags='CCK+2GHz', \
            ChannelFrequency = 2457, \
            RXFlags=0, \
            timestamp=26826669995, # int(time.time())
            mac_timestamp=2489957678 ,  # int(time.time()) 
            ts_accuracy=22, \
            ts_position=17, \
            ts_flags=3, \
            notdecoded='\x1f\x00\x1f\x01', \
            len=56
            )

        fcs = Dot11FCS(subtype=4, \
                        type=0, \
                        proto=0, FCfield=0, \
                        ID=0, addr1=dst, addr2=self.source, addr3=dst, \
                        SC=43296, fcs=0x8ad285da)

        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID', len=0, info=ssid)
        rates = Dot11Elt(ID='Supported Rates', len=4, info=self.rates)
        extrates = Dot11Elt(ID='Extended Supported Rates', len=8, info=self.extrates)
        dsset = Dot11Elt(ID='DSset', len=1, info='\x0a')
        htcapabilities = Dot11EltHTCapabilities( \
            Short_GI_20Mhz=1, \
            RX_MSC_Bitmask = 0xff, \
            Max_A_MPDU_Length_Exponent = 3, \
            Min_MPDCU_Start_Spacing = 5
            )
        extcapabilities = Dot11Elt(ID=127, info=self.extcapabilities)
        vendor = Dot11EltVendorSpecific(len=9, oui=0x001018, info="\x02\x00\x00\x1c\x00\x00")
        
        
        packet = radio/fcs/param/essid/rates/extrates/dsset/htcapabilities/extcapabilities/vendor
        
        sr1(packet, iface=self.intfmon, inter=0.2, verbose=1)
        



