//! Exact, nonnegative amounts and explicit koinu/1,000-vbyte fee rates.
use core::{fmt, str::FromStr};

pub const KOINU_PER_DOGE: u64 = 100_000_000;

/// A nonnegative integer count of koinu. No monetary-policy cap is imposed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Amount(u64);

impl Amount {
    pub const ZERO: Self = Self(0);
    pub const ONE_DOGE: Self = Self(KOINU_PER_DOGE);
    pub const MAX: Self = Self(u64::MAX);

    pub const fn from_koinu(koinu: u64) -> Self {
        Self(koinu)
    }

    pub const fn to_koinu(self) -> u64 {
        self.0
    }

    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn checked_mul(self, rhs: u64) -> Option<Self> {
        match self.0.checked_mul(rhs) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn checked_div(self, rhs: u64) -> Option<Self> {
        match self.0.checked_div(rhs) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Parse an unsigned decimal DOGE amount, optionally with an `e`/`E` exponent.
    ///
    /// Matches the existing DogeOS RPC conversion: effective decimal scale must
    /// not exceed eight, even for zero or redundant fractional zeroes. Exponents
    /// fit in `i32`; the decimal coefficient and power of ten fit in `u128`.
    /// No floating-point conversion or rounding occurs. The legacy text syntax
    /// also accepts `.1`, `1.` and `.`; an RPC caller must validate JSON separately.
    pub fn from_doge_str(text: &str) -> Result<Self, ParseAmountError> {
        text.parse()
    }
}

/// DOGE text always displays eight fractional digits, without a unit suffix.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:08}",
            self.0 / KOINU_PER_DOGE,
            self.0 % KOINU_PER_DOGE
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseAmountError {
    InvalidSyntax,
    Negative,
    TooPrecise,
    Overflow,
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSyntax => "expected an unsigned DOGE decimal",
            Self::Negative => "negative amounts are not valid outputs",
            Self::TooPrecise => "DOGE decimal scale exceeds eight places",
            Self::Overflow => "amount or exponent is out of range",
        })
    }
}

impl core::error::Error for ParseAmountError {}

impl FromStr for Amount {
    type Err = ParseAmountError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        use ParseAmountError::{InvalidSyntax, Negative, Overflow, TooPrecise};
        if text.starts_with('-') {
            return Err(Negative);
        }
        let (mantissa, exponent) = match text.split_once('e').or_else(|| text.split_once('E')) {
            Some((mantissa, exponent)) => (
                mantissa,
                exponent.parse::<i32>().map_err(|_| InvalidSyntax)?,
            ),
            None => (text, 0),
        };
        let (whole, fraction) = match mantissa.split_once('.') {
            Some((whole, fraction)) => (whole, fraction),
            None if !mantissa.is_empty() => (mantissa, ""),
            None => return Err(InvalidSyntax),
        };
        if !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|digit| digit.is_ascii_digit())
        {
            return Err(InvalidSyntax);
        }
        let mut coefficient = 0u128;
        for digit in whole.bytes().chain(fraction.bytes()) {
            coefficient = coefficient
                .checked_mul(10)
                .and_then(|v| v.checked_add(u128::from(digit - b'0')))
                .ok_or(Overflow)?;
        }
        let fractional_digits = i32::try_from(fraction.len()).map_err(|_| InvalidSyntax)?;
        let scale = fractional_digits.checked_sub(exponent).ok_or(Overflow)?;
        if scale > 8 {
            return Err(TooPrecise);
        }
        let power = 8i32.checked_sub(scale).ok_or(Overflow)? as u32;
        let multiplier = 10u128.checked_pow(power).ok_or(Overflow)?;
        let koinu = coefficient.checked_mul(multiplier).ok_or(Overflow)?;
        u64::try_from(koinu).map(Self).map_err(|_| Overflow)
    }
}

/// A budget rate in koinu per 1,000 virtual bytes (kvB, not KiB).
///
/// Fees round upward. This is a budgeting rule, not a reproduction of a node's
/// historical relay-fee or dust policy. Legacy Dogecoin bytes equal virtual bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FeeRate(u64);

impl FeeRate {
    pub const ZERO: Self = Self(0);

    pub const fn from_koinu_per_kvb(koinu_per_kvb: u64) -> Self {
        Self(koinu_per_kvb)
    }

    pub const fn to_koinu_per_kvb(self) -> u64 {
        self.0
    }

    /// Checked upward-rounded fee; wide intermediates avoid spurious overflow.
    pub const fn fee_for_vbytes(self, vbytes: u64) -> Option<Amount> {
        let fee = (self.0 as u128 * vbytes as u128).div_ceil(1_000);
        if fee > u64::MAX as u128 {
            None
        } else {
            Some(Amount(fee as u64))
        }
    }

    pub const fn fee_for_bytes(self, bytes: u64) -> Option<Amount> {
        self.fee_for_vbytes(bytes)
    }
}
