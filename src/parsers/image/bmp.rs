//! BMP (Bitmap) image format parser.

use crate::core::{FileFormat, FileReader, FormatParser, MetadataMap, TagValue};
use crate::error::{ExifToolError, Result};
use crate::exiftool_tables::{DecodedField, DecodedValue, decode_binary_table, find_table};
use crate::io::ByteOrder;

const BMP_SIGNATURE: &[u8] = b"BM";
const FILE_HEADER_LEN: u64 = 14;

/// BMP parser for ExifTool's Windows and OS/2 DIB header tables.
pub struct BMPParser;

impl BMPParser {
    /// Verifies the two-byte BMP signature.
    pub fn verify_signature(reader: &dyn FileReader) -> Result<bool> {
        if reader.size() < BMP_SIGNATURE.len() as u64 {
            return Ok(false);
        }
        Ok(reader.read(0, BMP_SIGNATURE.len())? == BMP_SIGNATURE)
    }

    fn dib_header<'a>(reader: &'a dyn FileReader) -> Result<(&'a [u8], &'static str)> {
        // ExifTool 13.30, lib/Image/ExifTool/BMP.pm, ProcessBMP:
        // read 18 bytes, require `BM`, read the little-endian DIB length at
        // file offset 14, and accept 12/16 or a length in [40, 1_000_000).
        if reader.size() < 18 || !Self::verify_signature(reader)? {
            return Err(ExifToolError::parse_error("Invalid BMP header"));
        }

        let prefix = reader.read(0, 18)?;
        let dib_len = u32::from_le_bytes(
            prefix[14..18]
                .try_into()
                .expect("the 18-byte prefix contains the DIB length"),
        );
        if dib_len != 12 && dib_len != 16 && !(40..1_000_000).contains(&dib_len) {
            return Err(ExifToolError::parse_error("Invalid BMP DIB header length"));
        }

        let dib_len = usize::try_from(dib_len)
            .map_err(|_| ExifToolError::parse_error("BMP DIB header is too large"))?;
        let end = FILE_HEADER_LEN
            .checked_add(dib_len as u64)
            .ok_or_else(|| ExifToolError::parse_error("BMP DIB header length overflow"))?;
        if end > reader.size() {
            return Err(ExifToolError::parse_error("Truncated BMP DIB header"));
        }

        // ProcessBMP selects the OS2 table for 12, 16, and 64-byte headers.
        let table = if matches!(dib_len, 12 | 16 | 64) {
            "OS2"
        } else {
            "Main"
        };
        Ok((reader.read(FILE_HEADER_LEN, dib_len)?, table))
    }

    fn integer(decoded: &DecodedField) -> Option<i64> {
        match decoded.raw {
            DecodedValue::Integer(value) => Some(value),
            _ => None,
        }
    }

    fn int_enum_or_unknown(decoded: &DecodedField) -> Option<TagValue> {
        let raw = Self::integer(decoded)?;
        Some(TagValue::String(
            decoded
                .apply_print_conv_to_raw()
                .unwrap_or_else(|| format!("Unknown ({raw})")),
        ))
    }

    fn compression(decoded: &DecodedField) -> Option<TagValue> {
        let raw = Self::integer(decoded)?;
        if raw <= 256 {
            return Some(
                decoded
                    .apply_print_conv_to_raw()
                    .map(TagValue::String)
                    .unwrap_or(TagValue::Integer(raw)),
            );
        }

        // ExifTool 13.30 BMP.pm, Main tag 16 ValueConv and PrintConv OTHER:
        // `$val > 256 ? unpack("A4",pack("V",$val)) : $val`, followed by
        // escaping every control or non-ASCII byte as `\xNN`.
        let raw = u32::try_from(raw).ok()?;
        let mut bytes = raw.to_le_bytes().to_vec();
        while matches!(bytes.last(), Some(0 | b' ')) {
            bytes.pop();
        }
        let mut rendered = String::new();
        for byte in bytes {
            if (0x20..=0x7e).contains(&byte) {
                rendered.push(char::from(byte));
            } else {
                rendered.push_str(&format!("\\x{byte:02x}"));
            }
        }
        Some(TagValue::String(rendered))
    }

    fn color_space(decoded: &DecodedField) -> Option<(String, TagValue)> {
        let DecodedValue::Undefined(bytes) = &decoded.raw else {
            return None;
        };
        let bytes: [u8; 4] = bytes.as_slice().try_into().ok()?;

        // ExifTool 13.30 BMP.pm, Main tag 56 RawConv:
        // `$val =~ /\0/ ? Get32u(\$val, 0) : pack("N",unpack("V",$val))`.
        // SetByteOrder('II') in ProcessBMP makes Get32u little-endian.
        let key = if bytes.contains(&0) {
            u32::from_le_bytes(bytes).to_string()
        } else {
            String::from_utf8(bytes.into_iter().rev().collect()).ok()?
        };
        let rendered = match key.as_str() {
            "0" => "Calibrated RGB".to_string(),
            "1" => "Device RGB".to_string(),
            "2" => "Device CMYK".to_string(),
            "LINK" => "Linked Color Profile".to_string(),
            "MBED" => "Embedded Color Profile".to_string(),
            "sRGB" => "sRGB".to_string(),
            "Win " => "Windows Color Space".to_string(),
            _ => key.clone(),
        };
        Some((key, TagValue::String(rendered)))
    }

    fn main_value(decoded: &DecodedField, color_space: &mut Option<String>) -> Option<TagValue> {
        match decoded.field.name {
            // RawConv stores the value for later branching but does not alter it.
            "BMPVersion" | "RenderingIntent" => Self::int_enum_or_unknown(decoded),
            // BMP.pm Main tag 8 ValueConv: `abs($val)`.
            "ImageHeight" => Some(TagValue::Integer(Self::integer(decoded)?.abs())),
            "Compression" => Self::compression(decoded),
            // BMP.pm Main tags 32 and 36 PrintConv expressions.
            "NumColors" => Some(match Self::integer(decoded)? {
                0 => TagValue::String("Use BitDepth".to_string()),
                value => TagValue::Integer(value),
            }),
            "NumImportantColors" => Some(match Self::integer(decoded)? {
                0 => TagValue::String("All".to_string()),
                value => TagValue::Integer(value),
            }),
            // BMP.pm Main tags 40, 44, 48, and 52:
            // `sprintf("0x%.8x",$val)`.
            "RedMask" | "GreenMask" | "BlueMask" | "AlphaMask" => Some(TagValue::String(format!(
                "0x{:08x}",
                u32::try_from(Self::integer(decoded)?).ok()?
            ))),
            "ColorSpace" => {
                let (key, mut value) = Self::color_space(decoded)?;
                // GetValue in ExifTool.pm renders an unmapped hash PrintConv
                // as `Unknown ($val)` when no OTHER conversion is registered.
                if !matches!(
                    key.as_str(),
                    "0" | "1" | "2" | "LINK" | "MBED" | "sRGB" | "Win "
                ) {
                    value = TagValue::String(format!("Unknown ({key})"));
                }
                *color_space = Some(key);
                Some(value)
            }
            // BMP.pm emits these only for LINK or MBED color spaces. The
            // generated table carries the fields but not this Condition, so
            // preserve the source branch here instead of over-emitting them.
            "ProfileDataOffset" | "ProfileSize"
                if !matches!(color_space.as_deref(), Some("LINK" | "MBED")) =>
            {
                None
            }
            // These generated fields have no value-changing conversion.
            "ImageWidth" | "Planes" | "BitDepth" | "ImageLength" | "PixelsPerMeterX"
            | "PixelsPerMeterY" | "ProfileDataOffset" | "ProfileSize" => decoded.to_tag_value(),
            // A newly generated field must receive a source conversion audit
            // before this parser starts emitting it.
            _ => None,
        }
    }

    fn parse_dib(data: &[u8], table_name: &'static str) -> Result<MetadataMap> {
        let table = find_table("BMP", table_name).ok_or_else(|| {
            ExifToolError::parse_error(format!("Generated BMP::{table_name} table is missing"))
        })?;
        // BMP.pm Main tag 36 Hook:
        // `$varSize += $size if $$self{BMPVersion} == 68`. The 68-byte AVI
        // header has one invalid 4-byte slot after NumImportantColors, so all
        // subsequent table offsets move by four bytes. The generated schema
        // deliberately has no Hook support; removing that slot presents the
        // same logical record to the shared decoder without approximating it.
        let avi_data;
        let data = if table_name == "Main" && data.len() == 68 {
            avi_data = [
                data.get(..40).unwrap_or_default(),
                data.get(44..).unwrap_or_default(),
            ]
            .concat();
            avi_data.as_slice()
        } else {
            data
        };
        let mut metadata = MetadataMap::new();
        let mut color_space = None;

        for decoded in decode_binary_table(table, data, ByteOrder::Little) {
            let value = if table_name == "Main" {
                Self::main_value(&decoded, &mut color_space)
            } else {
                // ExifTool 13.30 BMP.pm `%BMP::OS2`: only BMPVersion has a
                // PrintConv and none of the five fields has a ValueConv.
                if decoded.field.name == "BMPVersion" {
                    Self::int_enum_or_unknown(&decoded)
                } else {
                    decoded.to_tag_value()
                }
            };
            if let Some(value) = value {
                metadata.insert(format!("{}:{}", table.group0, decoded.field.name), value);
            }
        }
        Ok(metadata)
    }
}

impl FormatParser for BMPParser {
    fn parse(&self, reader: &dyn FileReader) -> Result<MetadataMap> {
        let (dib, table_name) = Self::dib_header(reader)?;
        Self::parse_dib(dib, table_name)
    }

    fn supports_format(&self, format: FileFormat) -> bool {
        matches!(format, FileFormat::BMP)
    }
}

/// Parses metadata from BMP files.
pub fn parse_bmp_metadata(reader: &dyn FileReader) -> std::result::Result<MetadataMap, String> {
    BMPParser.parse(reader).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::BufferedReader;

    fn windows_v3_fixture(height: i32, compression: u32) -> BufferedReader {
        let mut data = vec![0; 54];
        data[..2].copy_from_slice(BMP_SIGNATURE);
        data[14..18].copy_from_slice(&40_u32.to_le_bytes());
        data[18..22].copy_from_slice(&8_u32.to_le_bytes());
        data[22..26].copy_from_slice(&height.to_le_bytes());
        data[26..28].copy_from_slice(&1_u16.to_le_bytes());
        data[28..30].copy_from_slice(&8_u16.to_le_bytes());
        data[30..34].copy_from_slice(&compression.to_le_bytes());
        data[34..38].copy_from_slice(&64_u32.to_le_bytes());
        data[38..42].copy_from_slice(&2835_u32.to_le_bytes());
        data[42..46].copy_from_slice(&2835_u32.to_le_bytes());
        data[46..50].copy_from_slice(&256_u32.to_le_bytes());
        data[50..54].copy_from_slice(&256_u32.to_le_bytes());
        BufferedReader::from_bytes(&data)
    }

    #[test]
    fn windows_v3_matches_exiftool_13_30_bmp_corpus_expectations() {
        // Oracle: exiftool 13.30 -G -s -j -a t/images/BMP.bmp.
        let metadata = BMPParser
            .parse(&windows_v3_fixture(8, 0))
            .expect("valid Windows V3 BMP");
        let expected = [
            ("File:BMPVersion", TagValue::String("Windows V3".into())),
            ("File:ImageWidth", TagValue::Integer(8)),
            ("File:ImageHeight", TagValue::Integer(8)),
            ("File:Planes", TagValue::Integer(1)),
            ("File:BitDepth", TagValue::Integer(8)),
            ("File:Compression", TagValue::String("None".into())),
            ("File:ImageLength", TagValue::Integer(64)),
            ("File:PixelsPerMeterX", TagValue::Integer(2835)),
            ("File:PixelsPerMeterY", TagValue::Integer(2835)),
            ("File:NumColors", TagValue::Integer(256)),
            ("File:NumImportantColors", TagValue::Integer(256)),
        ];
        assert_eq!(metadata.len(), expected.len());
        for (name, value) in expected {
            assert_eq!(metadata.get(name), Some(&value), "{name}");
        }
        assert!(!metadata.contains_key("BMP:Width"));
        assert!(!metadata.contains_key("BMP:ImageSize"));
    }

    #[test]
    fn windows_height_valueconv_and_ascii_compression_match_bmp_pm() {
        let compression = u32::from_le_bytes(*b"MJPG");
        let metadata = BMPParser
            .parse(&windows_v3_fixture(-8, compression))
            .expect("valid top-down Windows BMP");
        assert_eq!(
            metadata.get("File:ImageHeight"),
            Some(&TagValue::Integer(8))
        );
        assert_eq!(
            metadata.get("File:Compression"),
            Some(&TagValue::String("MJPG".into()))
        );
    }

    #[test]
    fn os2_header_selects_exiftool_os2_table() {
        let mut data = vec![0; 26];
        data[..2].copy_from_slice(BMP_SIGNATURE);
        data[14..18].copy_from_slice(&12_u32.to_le_bytes());
        data[18..20].copy_from_slice(&320_u16.to_le_bytes());
        data[20..22].copy_from_slice(&200_u16.to_le_bytes());
        data[22..24].copy_from_slice(&1_u16.to_le_bytes());
        data[24..26].copy_from_slice(&4_u16.to_le_bytes());

        let metadata = BMPParser
            .parse(&BufferedReader::from_bytes(&data))
            .expect("valid OS/2 V1 BMP");
        assert_eq!(
            metadata.get("File:BMPVersion"),
            Some(&TagValue::String("OS/2 V1".into()))
        );
        assert_eq!(
            metadata.get("File:ImageWidth"),
            Some(&TagValue::Integer(320))
        );
        assert_eq!(
            metadata.get("File:ImageHeight"),
            Some(&TagValue::Integer(200))
        );
    }

    #[test]
    fn avi_header_applies_bmp_pm_variable_size_hook() {
        let mut data = vec![0; 82];
        data[..2].copy_from_slice(BMP_SIGNATURE);
        data[14..18].copy_from_slice(&68_u32.to_le_bytes());
        data[18..22].copy_from_slice(&8_u32.to_le_bytes());
        data[22..26].copy_from_slice(&8_i32.to_le_bytes());
        data[26..28].copy_from_slice(&1_u16.to_le_bytes());
        data[28..30].copy_from_slice(&24_u16.to_le_bytes());
        // LCS_sRGB (0x73524742), stored little-endian at the hooked offset.
        data[74..78].copy_from_slice(b"BGRs");

        let metadata = BMPParser
            .parse(&BufferedReader::from_bytes(&data))
            .expect("valid AVI BMP header");
        assert_eq!(
            metadata.get("File:BMPVersion"),
            Some(&TagValue::String("AVI BMP structure?".into()))
        );
        assert_eq!(
            metadata.get("File:ColorSpace"),
            Some(&TagValue::String("sRGB".into()))
        );
    }

    #[test]
    fn rejects_dib_lengths_process_bmp_rejects() {
        let mut data = vec![0; 54];
        data[..2].copy_from_slice(BMP_SIGNATURE);
        data[14..18].copy_from_slice(&20_u32.to_le_bytes());
        assert!(BMPParser.parse(&BufferedReader::from_bytes(&data)).is_err());

        data[14..18].copy_from_slice(&124_u32.to_le_bytes());
        assert!(BMPParser.parse(&BufferedReader::from_bytes(&data)).is_err());
    }
}
