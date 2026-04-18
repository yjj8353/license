use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// 라이선스 발급 유형
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceType {

    // 최초 발급
    Initial,

    // 갱신
    Renewal,

    // 업그레이드
    Upgrade,

    // 재발급 - 재발급 사유 필수
    Reissue,
}

/// 문자열에서 IssuanceType으로 변환
impl FromStr for IssuanceType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "initial" => Ok(Self::Initial),
            "renewal" => Ok(Self::Renewal),
            "upgrade" => Ok(Self::Upgrade),
            "reissue" => Ok(Self::Reissue),
            _ => Err("invalid issuance_type"),
        }
    }
}

/// 재발급 사유
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReissueReason {

    // 라이선스 분실
    LostLicense,

    // 도메인 교체
    DomainChange,

    // 하드웨어 교체
    HardwareChange,

    // 데이터 수정
    DataCorrection,

    // 라이선스 유출 및 보안사고
    SecurityIncident,
}

/// 문자열에서 ReissueReason으로 변환
impl FromStr for ReissueReason {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "lost_license" => Ok(Self::LostLicense),
            "domain_change" => Ok(Self::DomainChange),
            "hardware_change" => Ok(Self::HardwareChange),
            "data_correction" => Ok(Self::DataCorrection),
            "security_incident" => Ok(Self::SecurityIncident),
            _ => Err("invalid reissue_reason"),
        }
    }
}

/// 라이선스 정보 구조체
#[derive(Debug, Serialize, Deserialize)]
pub struct License {

    // 제품명
    pub product_name: String,

    // 라이선스 유형
    pub issuance_type: IssuanceType,

    // 재발급 사유
    pub reissue_reason: Option<ReissueReason>,

    // 라이선스 키
    pub license_key: String,

    // 도메인
    pub domain: String,

    // 발급일자
    pub issued_at: String,

    // 만료일자
    pub expires_at: String,

    // 서명
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    // 라이선스 스키마 버전
    pub license_version: String,
}

/// License 구조체의 메서드 구현
impl License {
    pub fn new(
        product_name: String,
        issuance_type: IssuanceType,
        reissue_reason: Option<ReissueReason>,
        license_key: String,
        domain: String,
        issued_at: String,
        expires_at: String,
        signature: Option<String>,
        license_version: String,
    ) -> Self {
        Self {
            product_name,
            issuance_type,
            reissue_reason,
            license_key,
            domain,
            issued_at,
            expires_at,
            signature,
            license_version,
        }
    }

    /// JSON 문자열로 변경
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// JSON 문자열을 License 구조체로 변경
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// 라이선스 정보의 유효성 검사
    pub fn validate(&self) -> Result<(), &'static str> {
        match (&self.issuance_type, &self.reissue_reason) {
            (IssuanceType::Reissue, Some(_)) => Ok(()),
            (IssuanceType::Reissue, None) => Err("reissue_reason is required for reissue licenses"),
            (_, None) => Ok(()),
            (_, Some(_)) => Err("reissue_reason is only allowed when issuance_type is reissue"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{IssuanceType, License, ReissueReason};

    fn sample_license() -> License {
        License {
            product_name: "Dashboard".to_string(),
            issuance_type: IssuanceType::Initial,
            reissue_reason: None,
            license_key: "XXXX-YYYY-ZZZZ-AAAA".to_string(),
            domain: "example.com".to_string(),
            issued_at: "2026-04-12T00:00:00Z".to_string(),
            expires_at: "2027-04-12T00:00:00Z".to_string(),
            signature: Some("base64encodedSig==".to_string()),
            license_version: "1.0".to_string(),
        }
    }

    #[test]
    fn to_json_produces_valid_json() {
        let json = sample_license().to_json().expect("직렬화 실패");

        assert!(json.contains("license_key"));
        assert!(json.contains("XXXX-YYYY-ZZZZ-AAAA"));
        assert!(json.contains("example.com"));
    }

    #[test]
    fn from_json_restores_all_fields() {
        let original = sample_license();
        let json = original.to_json().expect("직렬화 실패");
        let restored = License::from_json(&json).expect("역직렬화 실패");

        assert_eq!(restored.license_key, original.license_key);
        assert_eq!(restored.domain, original.domain);
        assert_eq!(restored.issued_at, original.issued_at);
        assert_eq!(restored.expires_at, original.expires_at);
        assert_eq!(restored.signature, original.signature);
        assert_eq!(restored.license_version, original.license_version);
    }

    #[test]
    fn round_trip_is_lossless() {
        let json = sample_license().to_json().expect("직렬화 실패");
        let json2 = License::from_json(&json)
            .expect("역직렬화 실패")
            .to_json()
            .expect("재직렬화 실패");

        assert_eq!(json, json2);
    }

    #[test]
    fn from_json_returns_error_on_invalid_input() {
        let result = License::from_json("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn issuance_type_from_str_parses_known_values() {
        assert_eq!(IssuanceType::from_str("initial"), Ok(IssuanceType::Initial));
        assert_eq!(IssuanceType::from_str("renewal"), Ok(IssuanceType::Renewal));
        assert_eq!(IssuanceType::from_str("upgrade"), Ok(IssuanceType::Upgrade));
        assert_eq!(IssuanceType::from_str("reissue"), Ok(IssuanceType::Reissue));
    }

    #[test]
    fn reissue_reason_from_str_parses_known_values() {
        assert_eq!(ReissueReason::from_str("lost_license"), Ok(ReissueReason::LostLicense));
        assert_eq!(
            ReissueReason::from_str("hardware_change"),
            Ok(ReissueReason::HardwareChange)
        );
    }

    #[test]
    fn validate_requires_reason_for_reissue() {
        let mut license = sample_license();
        license.issuance_type = IssuanceType::Reissue;

        assert_eq!(
            license.validate(),
            Err("reissue_reason is required for reissue licenses")
        );
    }

    #[test]
    fn validate_rejects_reason_for_non_reissue() {
        let mut license = sample_license();
        license.reissue_reason = Some(ReissueReason::HardwareChange);

        assert_eq!(
            license.validate(),
            Err("reissue_reason is only allowed when issuance_type is reissue")
        );
    }

    #[test]
    fn validate_accepts_reissue_with_reason() {
        let mut license = sample_license();
        license.issuance_type = IssuanceType::Reissue;
        license.reissue_reason = Some(ReissueReason::HardwareChange);

        assert_eq!(license.validate(), Ok(()));
    }
}
