use neli::{
    consts::{
        nl::NlmF,
        rtnl::{Ifla, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    nl::NlPayload,
    router::synchronous::NlRouter,
    rtnl::{Ifinfomsg, IfinfomsgBuilder},
    utils::Groups,
};

use crate::xdp::error::{self, Error};

pub fn get_mtu(if_index: i32) -> error::Result<u32> {
    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())
        .map_err(|e| Error::GetMtu(e.to_string()))?;

    let ifinfomsg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Netlink)
        .ifi_index(if_index)
        .build()
        .map_err(|e| Error::GetMtu(e.to_string()))?;

    let recv = rtnl
        .send::<_, _, Rtm, Ifinfomsg>(
            Rtm::Getlink,
            NlmF::DUMP_FILTERED | NlmF::REQUEST,
            NlPayload::Payload(ifinfomsg),
        )
        .map_err(|e| Error::GetMtu(e.to_string()))?;

    for response in recv {
        let mut response = response.map_err(|e| Error::GetMtu(e.to_string()))?;
        if let Some(payload) = response.get_payload() {
            return payload
                .rtattrs()
                .get_attr_handle()
                .get_attr_payload_as::<u32>(Ifla::Mtu)
                .map_err(|e| Error::GetMtu(e.to_string()));
        }
        if let Some(err) = response.get_err() {
            return Err(Error::GetMtu(err.to_string()));
        }
    }
    Err(Error::GetMtu(format!("Interface {} not found", if_index)))
}
