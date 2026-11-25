use alloc::boxed::Box;
use core::{fmt, str::FromStr};
use planchet_primitives::Amount;
pub use planchet_primitives::ParseAmountError as AmountError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;

/// A validated JSON number token, including its original exponent and trailing zeroes.
#[derive(Clone)]
pub struct JsonNumber(Box<RawValue>);
impl PartialEq for JsonNumber {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for JsonNumber {}
impl JsonNumber {
    pub fn as_str(&self) -> &str {
        self.0.get()
    }
}
impl fmt::Debug for JsonNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
impl FromStr for JsonNumber {
    type Err = AmountError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw: Box<RawValue> = serde_json::from_str(s).map_err(|_| AmountError::InvalidSyntax)?;
        if !matches!(raw.get().as_bytes().first(), Some(b'-' | b'0'..=b'9')) {
            return Err(AmountError::InvalidSyntax);
        }
        Ok(Self(raw))
    }
}
impl<'de> Deserialize<'de> for JsonNumber {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(d)?;
        if !matches!(raw.get().as_bytes().first(), Some(b'-' | b'0'..=b'9')) {
            return Err(serde::de::Error::custom("expected JSON number"));
        }
        Ok(Self(raw))
    }
}
impl Serialize for JsonNumber {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

/// Non-negative DOGE amount retaining the JSON token and its exact integer koinu value.
/// There is no floating point conversion or implicit rounding. The upper bound is u64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcAmount {
    source: JsonNumber,
    amount: Amount,
}
impl RpcAmount {
    pub fn koinu(&self) -> u64 {
        self.amount.to_koinu()
    }
    pub fn amount(&self) -> Amount {
        self.amount
    }
    pub fn source_text(&self) -> &str {
        self.source.as_str()
    }
}
impl FromStr for RpcAmount {
    type Err = AmountError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let source: JsonNumber = s.parse()?;
        let amount = Amount::from_doge_str(source.as_str())?;
        Ok(Self { source, amount })
    }
}
impl<'de> Deserialize<'de> for RpcAmount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let source = JsonNumber::deserialize(d)?;
        let amount = Amount::from_doge_str(source.as_str()).map_err(serde::de::Error::custom)?;
        Ok(Self { source, amount })
    }
}
impl Serialize for RpcAmount {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.source.serialize(s)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    // Decimal-place arithmetic supplies independent integer expectations, never a float oracle.
    #[test]
    fn exact_decimal_vectors() {
        for (text, expected) in [
            ("0", 0),
            ("1e-8", 1),
            ("1.23456789", 123456789),
            ("2.50E+2", 25000000000),
            ("184467440737.09551615", u64::MAX),
        ] {
            let amount: RpcAmount = serde_json::from_str(text).unwrap();
            assert_eq!(amount.koinu(), expected);
            assert_eq!(amount.source_text(), text);
            assert_eq!(serde_json::to_string(&amount).unwrap(), text);
        }
    }
    #[test]
    fn rejects_negative_fractional_and_overflow() {
        for (text, expected) in [
            ("-1", AmountError::Negative),
            ("-0", AmountError::Negative),
            ("0.0000000100", AmountError::TooPrecise),
            ("1e-9", AmountError::TooPrecise),
            ("0.000000001", AmountError::TooPrecise),
            ("184467440737.09551616", AmountError::Overflow),
        ] {
            assert_eq!(text.parse::<RpcAmount>().unwrap_err(), expected);
        }
        for text in [
            "0e2147483648",
            "1e-2147483649",
            "1e999999999999999999999999999",
            "\"1\"",
            "null",
            "NaN",
            "01",
            "+1",
            "true",
            "[]",
        ] {
            assert!(text.parse::<RpcAmount>().is_err());
        }
    }
    #[test]
    fn numeric_source_is_preserved_beyond_f64() {
        let text = "9007199254740993.00000001e-2";
        let number: JsonNumber = serde_json::from_str(text).unwrap();
        assert_eq!(number.as_str(), text);
    }
}
