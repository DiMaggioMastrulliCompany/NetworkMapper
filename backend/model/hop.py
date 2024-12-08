from typing import Optional

from pydantic import BaseModel


class Hop(BaseModel):
    ip: str
    ttl: int
    rtt: float
    host: Optional[str]

    @classmethod
    def from_nmap_hop(cls, hop):
        return cls(
            ip=hop.get('ipaddr'),
            ttl=int(hop.get('ttl')),
            rtt=float(hop.get('rtt')),
            host=hop.get('host') or None
        )
