//! Build conversion utilities: scan records to MMDB format.

use crate::types::{
    Continent, Country, GatewayExport, MmdbRecord, OperationalData, ScanGwRecord, WhoisExport,
};

/// Convert a [`ScanGwRecord`] to a [`MmdbRecord`] for mmdbctl NDJSON output.
pub fn to_mmdb_record(rec: &ScanGwRecord) -> MmdbRecord {
    let autonomous_system_number = rec.as_num.as_deref().and_then(parse_asn);
    let autonomous_system_organization = rec.as_name.clone();

    let country = rec.country.as_deref().map(|iso| Country {
        iso_code: iso.to_owned(),
    });
    let continent = rec
        .country
        .as_deref()
        .and_then(continent_from_country)
        .map(|code| Continent {
            code: code.to_owned(),
        });

    let whois = build_whois_export(rec);
    let gateway = build_gateway_export(rec);
    let operational = build_operational(rec);

    MmdbRecord {
        range: rec.range.clone(),
        continent,
        country,
        autonomous_system_number,
        autonomous_system_organization,
        whois,
        gateway,
        operational,
        xlsx_matched: rec.xlsx.is_some(),
        gateway_found: rec.gateway.status == "inservice",
    }
}

/// Parse an AS number string like `"AS64496"` or `"64496"` into a `u32`.
#[must_use]
pub fn parse_asn(s: &str) -> Option<u32> {
    let digits = s.strip_prefix("AS").unwrap_or(s);
    digits.parse::<u32>().ok()
}

/// Map an ISO 3166-1 alpha-2 country code to a `GeoLite2` continent code.
///
/// Returns `None` for unknown country codes; the `continent` field is then
/// omitted from the MMDB record.
#[must_use]
pub fn continent_from_country(iso: &str) -> Option<&'static str> {
    match iso {
        // Asia
        "JP" | "CN" | "KR" | "TW" | "HK" | "MO" | "MN" | "SG" | "MY" | "TH" | "VN" | "PH"
        | "ID" | "IN" | "PK" | "BD" | "LK" | "NP" | "MM" | "KH" | "LA" | "BN" | "TL" | "AF"
        | "IR" | "IQ" | "SY" | "LB" | "JO" | "IL" | "PS" | "SA" | "AE" | "QA" | "KW" | "BH"
        | "OM" | "YE" | "KZ" | "UZ" | "TM" | "KG" | "TJ" | "AZ" | "AM" | "GE" | "TR" | "CY" => {
            Some("AS")
        }
        // Europe
        "GB" | "DE" | "FR" | "IT" | "ES" | "PT" | "NL" | "BE" | "LU" | "CH" | "AT" | "SE"
        | "NO" | "DK" | "FI" | "IS" | "IE" | "PL" | "CZ" | "SK" | "HU" | "RO" | "BG" | "HR"
        | "SI" | "RS" | "BA" | "ME" | "MK" | "AL" | "GR" | "EE" | "LV" | "LT" | "UA" | "BY"
        | "MD" | "RU" | "MT" | "LI" | "MC" | "SM" | "VA" | "AD" => Some("EU"),
        // North America
        "US" | "CA" | "MX" | "GT" | "BZ" | "HN" | "SV" | "NI" | "CR" | "PA" | "CU" | "JM"
        | "HT" | "DO" | "PR" | "TT" | "BB" | "LC" | "VC" | "GD" | "AG" | "DM" | "KN" | "BS"
        | "TC" | "KY" | "BM" | "AW" | "CW" | "SX" | "BQ" | "VI" | "VG" | "AI" | "MS" | "MF"
        | "GP" | "MQ" | "PM" => Some("NA"),
        // South America
        "BR" | "AR" | "CL" | "CO" | "PE" | "VE" | "EC" | "BO" | "PY" | "UY" | "GY" | "SR"
        | "GF" | "FK" => Some("SA"),
        // Africa
        "ZA" | "NG" | "EG" | "KE" | "ET" | "GH" | "TZ" | "UG" | "DZ" | "MA" | "TN" | "LY"
        | "SD" | "SO" | "CM" | "CI" | "SN" | "ZW" | "ZM" | "MZ" | "AO" | "NA" | "BW" | "MW"
        | "RW" | "BI" | "DJ" | "ER" | "GA" | "CG" | "CD" | "CF" | "TD" | "NE" | "ML" | "BF"
        | "GN" | "GW" | "SL" | "LR" | "TG" | "BJ" | "MR" | "GM" | "CV" | "ST" | "GQ" | "SS"
        | "LS" | "SZ" | "KM" | "SC" | "MU" | "MG" | "RE" | "YT" | "EH" => Some("AF"),
        // Oceania
        "AU" | "NZ" | "FJ" | "PG" | "SB" | "VU" | "WS" | "TO" | "KI" | "FM" | "MH" | "PW"
        | "NR" | "TV" | "CK" | "NU" | "TK" | "WF" | "PF" | "NC" | "GU" | "MP" | "AS" | "UM"
        | "CX" | "CC" | "NF" | "HM" => Some("OC"),
        // Antarctica
        "AQ" | "TF" | "GS" | "BV" => Some("AN"),
        _ => None,
    }
}

fn build_whois_export(rec: &ScanGwRecord) -> Option<WhoisExport> {
    let all_none = rec.inetnum.is_none()
        && rec.netname.is_none()
        && rec.descr.is_none()
        && rec.whois_source.is_none()
        && rec.whois_last_modified.is_none();
    if all_none {
        return None;
    }
    Some(WhoisExport {
        inetnum: rec.inetnum.clone(),
        netname: rec.netname.clone(),
        descr: rec.descr.clone(),
        source: rec.whois_source.clone(),
        last_modified: rec.whois_last_modified.clone(),
    })
}

fn build_gateway_export(rec: &ScanGwRecord) -> Option<GatewayExport> {
    let gw = &rec.gateway;
    // Only emit gateway when there is meaningful data.
    if gw.ip.is_none() && gw.ptr.is_none() && gw.device.is_none() {
        return None;
    }
    let (device, device_role, facility, interface, facing) =
        gw.device
            .as_ref()
            .map_or((None, None, None, None, None), |d| {
                (
                    d.device.clone(),
                    d.device_role.clone(),
                    d.facility.clone(),
                    d.interface.clone(),
                    d.facing.clone(),
                )
            });
    Some(GatewayExport {
        ip: gw.ip.clone(),
        ptr: gw.ptr.clone(),
        device,
        device_role,
        facility,
        interface,
        facing,
    })
}

fn build_operational(rec: &ScanGwRecord) -> Option<OperationalData> {
    let xlsx = rec.xlsx.as_ref()?;
    let obj = xlsx.as_object()?;

    let source = obj.get("_source").and_then(|v| v.as_object());
    let filename = source
        .and_then(|s| s.get("file"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let sheetname = source
        .and_then(|s| s.get("sheet"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    // Build fields from all keys except _source.
    let fields: serde_json::Map<String, serde_json::Value> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "_source")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Some(OperationalData {
        filename,
        sheetname,
        last_modified: None,
        fields: serde_json::Value::Object(fields),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::indexing_slicing)]

    use serde_json::json;

    use crate::types::{GatewayDevice, GatewayInfo, ScanGwRecord};

    use super::*;

    fn base_record() -> ScanGwRecord {
        ScanGwRecord {
            range: "198.51.100.0/30".to_owned(),
            netname: Some("EXAMPLE-NET".to_owned()),
            descr: Some("Example Network".to_owned()),
            as_num: Some("AS64496".to_owned()),
            as_name: Some("Example Corp".to_owned()),
            as_descr: None,
            inetnum: Some("198.51.100.0 - 198.51.100.255".to_owned()),
            country: Some("JP".to_owned()),
            whois_source: Some("APNIC".to_owned()),
            whois_last_modified: Some("2025-01-15T00:00:00Z".to_owned()),
            gateway: GatewayInfo {
                ip: Some("198.51.100.1".to_owned()),
                ptr: Some("xe-0-0-1.rtr0101.colo05.example.com".to_owned()),
                votes: 7,
                total: 7,
                status: "inservice".to_owned(),
                device: Some(GatewayDevice {
                    interface: Some("xe-0-0-1".to_owned()),
                    device: Some("rtr0101".to_owned()),
                    device_role: Some("rtr".to_owned()),
                    facility: Some("colo05".to_owned()),
                    facing: Some("user".to_owned()),
                    customer_asn: None,
                }),
            },
            routes: vec![],
            host_ip: None,
            host_ptr: None,
            measured_at: Some("2026-05-09T07:18:05Z".to_owned()),
            xlsx: Some(json!({
                "_source": {"file": "IPAM.xlsx", "sheet": "border1.ty1", "row_index": 0},
                "serviceid": "SVC-001",
                "cableid": "C10001"
            })),
            xlsx_matched: false,
            gateway_found: false,
        }
    }

    // --- to_mmdb_record ---

    #[test]
    fn to_mmdb_record_full_mapping() {
        let rec = base_record();
        let mmdb = to_mmdb_record(&rec);

        assert_eq!(mmdb.range, "198.51.100.0/30");
        assert_eq!(mmdb.autonomous_system_number, Some(64496));
        assert_eq!(
            mmdb.autonomous_system_organization.as_deref(),
            Some("Example Corp")
        );
        assert_eq!(mmdb.country.as_ref().unwrap().iso_code, "JP");
        assert_eq!(mmdb.continent.as_ref().unwrap().code, "AS");

        let whois = mmdb.whois.as_ref().unwrap();
        assert_eq!(
            whois.inetnum.as_deref(),
            Some("198.51.100.0 - 198.51.100.255")
        );
        assert_eq!(whois.netname.as_deref(), Some("EXAMPLE-NET"));
        assert_eq!(whois.source.as_deref(), Some("APNIC"));
        assert_eq!(whois.last_modified.as_deref(), Some("2025-01-15T00:00:00Z"));

        let gw = mmdb.gateway.as_ref().unwrap();
        assert_eq!(gw.ip.as_deref(), Some("198.51.100.1"));
        assert_eq!(gw.device.as_deref(), Some("rtr0101"));
        assert_eq!(gw.facility.as_deref(), Some("colo05"));
        assert_eq!(gw.interface.as_deref(), Some("xe-0-0-1"));
        assert_eq!(gw.facing.as_deref(), Some("user"));

        let op = mmdb.operational.as_ref().unwrap();
        assert_eq!(op.filename, "IPAM.xlsx");
        assert_eq!(op.sheetname, "border1.ty1");
        assert_eq!(op.fields["serviceid"], "SVC-001");
        assert_eq!(op.fields["cableid"], "C10001");
        // _source must not leak into fields
        assert!(op.fields.get("_source").is_none());
    }

    #[test]
    fn to_mmdb_record_no_xlsx() {
        let mut rec = base_record();
        rec.xlsx = None;
        let mmdb = to_mmdb_record(&rec);
        assert!(mmdb.operational.is_none());
    }

    #[test]
    fn to_mmdb_record_no_gateway_ip_omits_gateway() {
        let mut rec = base_record();
        rec.gateway.ip = None;
        rec.gateway.ptr = None;
        rec.gateway.device = None;
        let mmdb = to_mmdb_record(&rec);
        assert!(mmdb.gateway.is_none());
    }

    #[test]
    fn to_mmdb_record_xlsx_matched_true() {
        // base_record has xlsx = Some(...) and status = "inservice"
        let rec = base_record();
        let mmdb = to_mmdb_record(&rec);
        assert!(mmdb.xlsx_matched);
        assert!(mmdb.gateway_found);
    }

    #[test]
    fn to_mmdb_record_no_xlsx_gateway_inservice() {
        let mut rec = base_record();
        rec.xlsx = None;
        let mmdb = to_mmdb_record(&rec);
        assert!(!mmdb.xlsx_matched);
        assert!(mmdb.gateway_found);
    }

    #[test]
    fn to_mmdb_record_xlsx_some_gateway_no_ptr_match() {
        let mut rec = base_record();
        rec.gateway.status = "no_ptr_match".to_owned();
        let mmdb = to_mmdb_record(&rec);
        assert!(mmdb.xlsx_matched);
        assert!(!mmdb.gateway_found);
    }

    #[test]
    fn to_mmdb_record_no_xlsx_no_hops() {
        let mut rec = base_record();
        rec.xlsx = None;
        rec.gateway.status = "no_hops".to_owned();
        let mmdb = to_mmdb_record(&rec);
        assert!(!mmdb.xlsx_matched);
        assert!(!mmdb.gateway_found);
    }

    #[test]
    fn to_mmdb_record_no_whois_omits_whois() {
        let mut rec = base_record();
        rec.inetnum = None;
        rec.netname = None;
        rec.descr = None;
        rec.whois_source = None;
        rec.whois_last_modified = None;
        let mmdb = to_mmdb_record(&rec);
        assert!(mmdb.whois.is_none());
    }

    // --- parse_asn ---

    #[test]
    fn parse_asn_with_prefix() {
        assert_eq!(parse_asn("AS64496"), Some(64496));
    }

    #[test]
    fn parse_asn_digits_only() {
        assert_eq!(parse_asn("64496"), Some(64496));
    }

    #[test]
    fn parse_asn_invalid_returns_none() {
        assert_eq!(parse_asn(""), None);
        assert_eq!(parse_asn("ASxyz"), None);
    }

    // --- continent_from_country ---

    #[test]
    fn continent_jp_is_asia() {
        assert_eq!(continent_from_country("JP"), Some("AS"));
    }

    #[test]
    fn continent_us_is_north_america() {
        assert_eq!(continent_from_country("US"), Some("NA"));
    }

    #[test]
    fn continent_gb_is_europe() {
        assert_eq!(continent_from_country("GB"), Some("EU"));
    }

    #[test]
    fn continent_au_is_oceania() {
        assert_eq!(continent_from_country("AU"), Some("OC"));
    }

    #[test]
    fn continent_za_is_africa() {
        assert_eq!(continent_from_country("ZA"), Some("AF"));
    }

    #[test]
    fn continent_br_is_south_america() {
        assert_eq!(continent_from_country("BR"), Some("SA"));
    }

    #[test]
    fn continent_unknown_returns_none() {
        assert_eq!(continent_from_country("XX"), None);
        assert_eq!(continent_from_country(""), None);
    }
}
