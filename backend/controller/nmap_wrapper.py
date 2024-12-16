from typing import override

from nmap import PortScanner, PortScannerError
from xml.etree import ElementTree as ET


class NmapWrapper(PortScanner):
    @override
    def analyse_nmap_xml_scan(
            self,
            nmap_xml_output=None,
            nmap_err="",
            nmap_err_keep_trace="",
            nmap_warn_keep_trace="",
    ):
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///C:/Program Files (x86)/Nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.95 scan initiated Thu Dec  5 16:00:51 2024 as: &quot;C:\\Program Files (x86)\\Nmap\\nmap.exe&quot; -&#45;traceroute -sn -oX - 49.12.234.183/31 -->
<nmaprun scanner="nmap" args="&quot;C:\\Program Files (x86)\\Nmap\\nmap.exe&quot; -&#45;traceroute -sn -oX - 49.12.234.183/31" start="1733410851" startstr="Thu Dec  5 16:00:51 2024" version="7.95" xmloutputversion="1.05">
<verbose level="0"/>
<debugging level="0"/>
<host starttime="0" endtime="0"><status state="up" reason="echo-reply" reason_ttl="54"/>
<address addr="49.12.234.182" addrtype="ipv4"/>
<hostnames>
<hostname name="static.182.234.12.49.clients.your-server.de" type="PTR"/>
</hostnames>
<trace proto="icmp">
<hop ttl="6" ipaddr="62.115.140.203" rtt="29.00" host="nug-b2-link.ip.twelve99.net"/>
<hop ttl="7" ipaddr="213.248.70.1" rtt="36.00" host="hetzner-ic-340780.ip.twelve99-cust.net"/>
<hop ttl="8" ipaddr="213.239.245.25" rtt="36.00" host="core12.nbg1.hetzner.com"/>
<hop ttl="9" ipaddr="213.239.239.142" rtt="36.00" host="spine16.cloud1.nbg1.hetzner.com"/>
<hop ttl="10" ipaddr="78.47.3.46" rtt="37.00" host="spine4.cloud1.nbg1.hetzner.com"/>
<hop ttl="12" ipaddr="49.12.141.119" rtt="36.00" host="17341.your-cloud.host"/>
<hop ttl="13" ipaddr="49.12.234.182" rtt="37.00" host="static.182.234.12.49.clients.your-server.de"/>
</trace>
<times srtt="37000" rttvar="27750" to="148000"/>
</host>
<host starttime="0" endtime="0"><status state="up" reason="echo-reply" reason_ttl="54"/>
<address addr="49.12.234.183" addrtype="ipv4"/>
<hostnames>
<hostname name="v4.ident.me" type="PTR"/>
</hostnames>
<trace proto="icmp">
<hop ttl="6" ipaddr="62.115.140.203" rtt="29.00" host="nug-b2-link.ip.twelve99.net"/>
<hop ttl="7" ipaddr="213.248.70.1" rtt="36.00" host="hetzner-ic-340780.ip.twelve99-cust.net"/>
<hop ttl="8" ipaddr="213.239.203.137" rtt="35.00" host="core11.nbg1.hetzner.com"/>
<hop ttl="9" ipaddr="213.239.239.122" rtt="36.00" host="spine16.cloud1.nbg1.hetzner.com"/>
<hop ttl="10" ipaddr="85.10.237.94" rtt="36.00" host="spine8.cloud1.nbg1.hetzner.com"/>
<hop ttl="12" ipaddr="195.201.67.161" rtt="37.00" host="11703.your-cloud.host"/>
<hop ttl="13" ipaddr="49.12.234.183" rtt="36.00" host="v4.ident.me"/>
</trace>
<times srtt="38625" rttvar="30000" to="158625"/>
</host>
<runstats><finished time="1733410867" timestr="Thu Dec  5 16:01:07 2024" summary="Nmap done at Thu Dec  5 16:01:07 2024; 2 IP addresses (2 hosts up) scanned in 15.44 seconds" elapsed="15.44" exit="success"/><hosts up="2" down="0" total="2"/>
</runstats>
</nmaprun>"""
        partial_scan_result = super().analyse_nmap_xml_scan(
            nmap_xml_output=nmap_xml_output,
            nmap_err=nmap_err,
            nmap_err_keep_trace=nmap_err_keep_trace,
            nmap_warn_keep_trace=nmap_warn_keep_trace,
        )

        if nmap_xml_output is not None:
            self._nmap_last_output = nmap_xml_output

        try:
            dom = ET.fromstring(self._nmap_last_output)

            # Merge trace information into missing_info_scan_result
            for host in dom.findall("host"):
                address = host.find("address").get("addr")
                trace = host.find("trace")
                if trace is not None:
                    hops = []
                    for hop in trace.findall("hop"):
                        hop_info = {
                            "ttl": int(hop.get("ttl")),
                            "ipaddr": hop.get("ipaddr"),
                            "rtt": float(hop.get("rtt")),
                            "host": hop.get("host", "")
                        }
                        hops.append(hop_info)
                    if address in partial_scan_result["scan"]:
                        partial_scan_result["scan"][address]["trace"] = hops

            self._scan_result = partial_scan_result
            return partial_scan_result

        except Exception as e:
            if len(nmap_err) > 0:
                raise PortScannerError(nmap_err)
            else:
                raise PortScannerError(self._nmap_last_output)
