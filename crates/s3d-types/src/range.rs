use crate::error::{S3Error, S3ErrorCode, StoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRangeSpec {
    /// `bytes=start-end` (inclusive)
    FromTo { start: u64, end: u64 },
    /// `bytes=start-`
    From { start: u64 },
    /// `bytes=-suffix_len`
    Suffix { len: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedRangeHeader {
    /// Valid single byte range request
    Single(ByteRangeSpec),
    /// Multi-range or unsupported unit ignored -> return full 200 OK object (FR-9 / Q3)
    Ignore,
    /// Syntactically invalid `bytes=` single range -> 416 InvalidRange (or ignored per S3)
    Invalid,
}

/// Parse an HTTP `Range` header according to FR-9.
pub fn parse_range_header(raw: &str) -> ParsedRangeHeader {
    let raw = raw.trim();
    let Some(rest) = raw.strip_prefix("bytes=") else {
        return ParsedRangeHeader::Ignore;
    };
    if rest.contains(',') {
        // FR-9 / Q3: multi-range requests ignore Range and return the whole object.
        return ParsedRangeHeader::Ignore;
    }
    let Some((lhs, rhs)) = rest.split_once('-') else {
        return ParsedRangeHeader::Invalid;
    };
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    match (lhs.is_empty(), rhs.is_empty()) {
        (true, true) => ParsedRangeHeader::Invalid,
        (true, false) => match rhs.parse::<u64>() {
            Ok(0) => ParsedRangeHeader::Invalid,
            Ok(len) => ParsedRangeHeader::Single(ByteRangeSpec::Suffix { len }),
            Err(_) => ParsedRangeHeader::Invalid,
        },
        (false, true) => match lhs.parse::<u64>() {
            Ok(start) => ParsedRangeHeader::Single(ByteRangeSpec::From { start }),
            Err(_) => ParsedRangeHeader::Invalid,
        },
        (false, false) => match (lhs.parse::<u64>(), rhs.parse::<u64>()) {
            (Ok(start), Ok(end)) if start <= end => {
                ParsedRangeHeader::Single(ByteRangeSpec::FromTo { start, end })
            }
            _ => ParsedRangeHeader::Invalid,
        },
    }
}

impl ByteRangeSpec {
    /// Resolve against `object_size`, returning inclusive `(start, end)` or `416 InvalidRange`.
    pub fn resolve(self, object_size: u64) -> StoreResult<(u64, u64)> {
        let invalid = || {
            S3Error::new(
                S3ErrorCode::InvalidRange,
                "The requested range is not satisfiable",
            )
            .with_header("Content-Range", format!("bytes */{object_size}"))
        };

        if object_size == 0 {
            return Err(invalid());
        }

        match self {
            ByteRangeSpec::FromTo { start, end } => {
                if start >= object_size {
                    return Err(invalid());
                }
                Ok((start, end.min(object_size - 1)))
            }
            ByteRangeSpec::From { start } => {
                if start >= object_size {
                    return Err(invalid());
                }
                Ok((start, object_size - 1))
            }
            ByteRangeSpec::Suffix { len } => {
                if len == 0 {
                    return Err(invalid());
                }
                let take = len.min(object_size);
                Ok((object_size - take, object_size - 1))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing_and_resolution() {
        let ParsedRangeHeader::Single(spec) = parse_range_header("bytes=0-4") else {
            panic!()
        };
        assert_eq!(spec.resolve(10).unwrap(), (0, 4));
        assert_eq!(spec.resolve(3).unwrap(), (0, 2));
        assert_eq!(spec.resolve(0).unwrap_err().code, S3ErrorCode::InvalidRange);

        let ParsedRangeHeader::Single(suf) = parse_range_header("bytes=-4") else {
            panic!()
        };
        assert_eq!(suf.resolve(10).unwrap(), (6, 9));
        assert_eq!(suf.resolve(2).unwrap(), (0, 1));

        assert_eq!(
            parse_range_header("bytes=0-1, 3-4"),
            ParsedRangeHeader::Ignore
        );
    }
}
