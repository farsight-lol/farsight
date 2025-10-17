use crate::controller::protocol::{Parser, ParseError};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow
    ,
    io::{Cursor, Read, Write},
    net::Ipv4Addr,
};
use crate::config::ParserKind;

#[derive(Default)]
pub struct SLPParser;

impl Parser for SLPParser {
    const KIND: ParserKind = ParserKind::Slp;

    type Output = SLPResponse;

    #[inline]
    fn parse(
        &'_ self,
        _ip: Ipv4Addr,
        _port: u16,
        data: &'_ [u8],
    ) -> Result<Self::Output, ParseError> {
        let mut stream = Cursor::new(data);

        // ignore packet length
        read_varint(&mut stream)?;

        let packet_id = read_varint(&mut stream)?;
        let response_length = read_varint(&mut stream)?;

        if packet_id != 0x00 || response_length <= 0 {
            return Err(ParseError::Invalid);
        }

        // read until end
        let position = stream.position() as usize;
        let status_buffer = &stream.into_inner()[position..];
        if status_buffer.len() < response_length as usize {
            return Err(ParseError::Incomplete);
        }

        match serde_json::from_slice(status_buffer) {
            Ok(value) => {
                Ok(value)
            }

            Err(_) => Err(ParseError::Invalid),
        }
    }
}

// copied from craftping (https://github.com/kiwiyou/craftping) - START
pub fn build_latest_request(
    hostname: &str,
    port: u16,
    protocol_version: i32,
) -> Vec<u8> {
    // buffer for the 1st packet's data part
    let mut buffer = vec![
        // 0 for handshake packet
        0x00,
    ];

    write_varint(&mut buffer, protocol_version); // protocol version

    // Some server implementations require hostname and port to be properly set
    // (Notchian does not)
    write_varint(&mut buffer, hostname.len() as i32); // length of hostname as VarInt
    buffer.extend_from_slice(hostname.as_bytes());
    buffer.extend_from_slice(&[
        (port >> 8) as u8,
        (port & 0b1111_1111) as u8, // server port as unsigned short
        0x01,                       // next state: 1 (status) as VarInt
    ]);
    // buffer for the 1st and 2nd packet
    let mut full_buffer = vec![];
    write_varint(&mut full_buffer, buffer.len() as i32); // length of 1st packet id + data as VarInt
    full_buffer.append(&mut buffer);
    full_buffer.extend_from_slice(&[
        1,    // length of 2nd packet id + data as VarInt
        0x00, // 2nd packet id: 0 for request as VarInt
    ]);

    // let mut f = std::fs::File::create("request.bin").unwrap();
    // f.write_all(&full_buffer).unwrap();

    full_buffer
}

#[inline]
fn write_varint(writer: &mut Vec<u8>, mut value: i32) {
    let mut buffer = [0];
    if value == 0 {
        writer.write_all(&buffer).unwrap();
    }

    while value != 0 {
        buffer[0] = (value & 0b0111_1111) as u8;
        value = (value >> 7) & (i32::MAX >> 6);
        if value != 0 {
            buffer[0] |= 0b1000_0000;
        }
        writer.write_all(&buffer).unwrap();
    }
}

#[inline]
fn read_varint(
    reader: &mut (impl Read + Unpin + Send),
) -> Result<i32, ParseError> {
    let mut buffer = [0];
    let mut ans = 0;

    for i in 0..5 {
        reader
            .read_exact(&mut buffer)
            .or(Err(ParseError::Incomplete))?;
        ans |= ((buffer[0] & 0b0111_1111) as i32) << (7 * i);

        if buffer[0] & 0b1000_0000 == 0 {
            break;
        }
    }

    Ok(ans)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SLPResponse {
    pub version: Version,
    pub players: Players,
    pub description: Option<serde_json::Value>,
    pub favicon: Option<String>,
    #[serde(rename = "enforcesSecureChat")]
    pub enforces_secure_chat: Option<bool>,
    #[serde(rename = "previewsChat")]
    pub previews_chat: Option<bool>,
    #[serde(rename = "modinfo")]
    pub mod_info: Option<ModInfo>,
    #[serde(rename = "forgeData")]
    pub forge_data: Option<ForgeData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Version {
    pub name: String,
    pub protocol: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Players {
    pub max: usize,
    pub online: usize,
    pub sample: Option<Vec<Player>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The sample players' information.
pub struct Player {
    /// The name of the player.
    pub name: String,
    /// The uuid of the player.
    /// Normally used to identify a player.
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The mod information object used in FML protocol (version 1.7 - 1.12).
pub struct ModInfo {
    #[serde(rename = "type")]
    /// The field `type` of `modinfo`. It should be FML if forge is installed.
    pub mod_type: String,
    #[serde(rename = "modList")]
    /// The list of the mod installed on the server.
    /// See also [`ModInfoItem`](ModInfoItem)
    pub mod_list: Vec<ModInfoItem>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The information of an installed mod.
pub struct ModInfoItem {
    #[serde(rename = "modid")]
    /// The id of the mod.
    pub mod_id: String,
    /// The version of the mod.
    pub version: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The forge information object used in FML2 protocol (version 1.13 - current).
pub struct ForgeData {
    /// The list of the channels used by the mods.
    /// See [the minecraft protocol wiki](https://wiki.vg/Plugin_channels) for more information.
    pub channels: Vec<ForgeChannel>,
    /// The list of the mods installed on the server.
    pub mods: Vec<ForgeMod>,
    #[serde(rename = "fmlNetworkVersion")]
    pub fml_network_version: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The information of the channels used by the mods.
///
/// See [the minecraft protocol wiki](https://wiki.vg/Plugin_channels) for more information.
/// Unfortunately, the exact semantics of its field is currently not found.
/// We do not guarantee the document is right, and you should re-check the values you've received.
pub struct ForgeChannel {
    /// The namespaced key of the channel
    pub res: String,
    /// The version of the channel
    pub version: String,
    /// `true` if it is required
    pub required: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// The information of an installed mod.
pub struct ForgeMod {
    #[serde(rename = "modId")]
    /// The id of the mod.
    pub mod_id: String,
    #[serde(rename = "modmarker")]
    /// The version of the mod.
    pub mod_marker: String,
}
// copied from craftping (https://github.com/kiwiyou/craftping) - END
