use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum S3ErrorCode {
    AccessControlListNotSupported,
    AccessDenied,
    AuthorizationHeaderMalformed,
    BadDigest,
    BadRequest,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    ConditionalRequestConflict,
    EntityTooLarge,
    EntityTooSmall,
    Forbidden,
    IncompleteBody,
    InternalError,
    InvalidAccessKeyId,
    InvalidArgument,
    InvalidBucketAclWithObjectOwnership,
    InvalidBucketName,
    InvalidDigest,
    InvalidLocationConstraint,
    InvalidPart,
    InvalidPartOrder,
    InvalidPolicyDocument,
    InvalidRange,
    InvalidRequest,
    InvalidStorageClass,
    InvalidTag,
    InvalidURI,
    KeyTooLongError,
    MalformedACLError,
    MalformedPolicy,
    MalformedXML,
    MetadataTooLarge,
    MethodNotAllowed,
    MissingContentLength,
    MissingSecurityHeader,
    NoSuchBucket,
    NoSuchBucketPolicy,
    NoSuchCorsConfiguration,
    NoSuchKey,
    NoSuchPublicAccessBlockConfiguration,
    NoSuchTagSet,
    NoSuchUpload,
    NoSuchVersion,
    NotImplemented,
    NotModified,
    OwnershipControlsNotFoundError,
    PreconditionFailed,
    RequestHeaderSectionTooLarge,
    RequestTimeTooSkewed,
    SignatureDoesNotMatch,
    SlowDown,
    TooManyBuckets,
    UnresolvableGrantByEmailAddress,
    XAmzContentSHA256Mismatch,
}

impl S3ErrorCode {
    pub const fn status_code(self) -> u16 {
        match self {
            Self::NotModified => 304,
            Self::AccessControlListNotSupported
            | Self::AuthorizationHeaderMalformed
            | Self::BadDigest
            | Self::BadRequest
            | Self::EntityTooLarge
            | Self::EntityTooSmall
            | Self::IncompleteBody
            | Self::InvalidArgument
            | Self::InvalidBucketAclWithObjectOwnership
            | Self::InvalidBucketName
            | Self::InvalidDigest
            | Self::InvalidLocationConstraint
            | Self::InvalidPart
            | Self::InvalidPartOrder
            | Self::InvalidPolicyDocument
            | Self::InvalidRequest
            | Self::InvalidStorageClass
            | Self::InvalidTag
            | Self::InvalidURI
            | Self::KeyTooLongError
            | Self::MalformedACLError
            | Self::MalformedPolicy
            | Self::MalformedXML
            | Self::MetadataTooLarge
            | Self::MissingSecurityHeader
            | Self::RequestHeaderSectionTooLarge
            | Self::TooManyBuckets
            | Self::UnresolvableGrantByEmailAddress
            | Self::XAmzContentSHA256Mismatch => 400,
            Self::AccessDenied
            | Self::Forbidden
            | Self::InvalidAccessKeyId
            | Self::RequestTimeTooSkewed
            | Self::SignatureDoesNotMatch => 403,
            Self::NoSuchBucket
            | Self::NoSuchBucketPolicy
            | Self::NoSuchCorsConfiguration
            | Self::NoSuchKey
            | Self::NoSuchPublicAccessBlockConfiguration
            | Self::NoSuchTagSet
            | Self::NoSuchUpload
            | Self::NoSuchVersion
            | Self::OwnershipControlsNotFoundError => 404,
            Self::MethodNotAllowed => 405,
            Self::BucketAlreadyExists
            | Self::BucketAlreadyOwnedByYou
            | Self::BucketNotEmpty
            | Self::ConditionalRequestConflict => 409,
            Self::MissingContentLength => 411,
            Self::PreconditionFailed => 412,
            Self::InvalidRange => 416,
            Self::InternalError => 500,
            Self::NotImplemented => 501,
            Self::SlowDown => 503,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccessControlListNotSupported => "AccessControlListNotSupported",
            Self::AccessDenied => "AccessDenied",
            Self::AuthorizationHeaderMalformed => "AuthorizationHeaderMalformed",
            Self::BadDigest => "BadDigest",
            Self::BadRequest => "BadRequest",
            Self::BucketAlreadyExists => "BucketAlreadyExists",
            Self::BucketAlreadyOwnedByYou => "BucketAlreadyOwnedByYou",
            Self::BucketNotEmpty => "BucketNotEmpty",
            Self::ConditionalRequestConflict => "ConditionalRequestConflict",
            Self::EntityTooLarge => "EntityTooLarge",
            Self::EntityTooSmall => "EntityTooSmall",
            Self::Forbidden => "Forbidden",
            Self::IncompleteBody => "IncompleteBody",
            Self::InternalError => "InternalError",
            Self::InvalidAccessKeyId => "InvalidAccessKeyId",
            Self::InvalidArgument => "InvalidArgument",
            Self::InvalidBucketAclWithObjectOwnership => "InvalidBucketAclWithObjectOwnership",
            Self::InvalidBucketName => "InvalidBucketName",
            Self::InvalidDigest => "InvalidDigest",
            Self::InvalidLocationConstraint => "InvalidLocationConstraint",
            Self::InvalidPart => "InvalidPart",
            Self::InvalidPartOrder => "InvalidPartOrder",
            Self::InvalidPolicyDocument => "InvalidPolicyDocument",
            Self::InvalidRange => "InvalidRange",
            Self::InvalidRequest => "InvalidRequest",
            Self::InvalidStorageClass => "InvalidStorageClass",
            Self::InvalidTag => "InvalidTag",
            Self::InvalidURI => "InvalidURI",
            Self::KeyTooLongError => "KeyTooLongError",
            Self::MalformedACLError => "MalformedACLError",
            Self::MalformedPolicy => "MalformedPolicy",
            Self::MalformedXML => "MalformedXML",
            Self::MetadataTooLarge => "MetadataTooLarge",
            Self::MethodNotAllowed => "MethodNotAllowed",
            Self::MissingContentLength => "MissingContentLength",
            Self::MissingSecurityHeader => "MissingSecurityHeader",
            Self::NoSuchBucket => "NoSuchBucket",
            Self::NoSuchBucketPolicy => "NoSuchBucketPolicy",
            Self::NoSuchCorsConfiguration => "NoSuchCorsConfiguration",
            Self::NoSuchKey => "NoSuchKey",
            Self::NoSuchPublicAccessBlockConfiguration => "NoSuchPublicAccessBlockConfiguration",
            Self::NoSuchTagSet => "NoSuchTagSet",
            Self::NoSuchUpload => "NoSuchUpload",
            Self::NoSuchVersion => "NoSuchVersion",
            Self::NotImplemented => "NotImplemented",
            Self::NotModified => "NotModified",
            Self::OwnershipControlsNotFoundError => "OwnershipControlsNotFoundError",
            Self::PreconditionFailed => "PreconditionFailed",
            Self::RequestHeaderSectionTooLarge => "RequestHeaderSectionTooLarge",
            Self::RequestTimeTooSkewed => "RequestTimeTooSkewed",
            Self::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            Self::SlowDown => "SlowDown",
            Self::TooManyBuckets => "TooManyBuckets",
            Self::UnresolvableGrantByEmailAddress => "UnresolvableGrantByEmailAddress",
            Self::XAmzContentSHA256Mismatch => "XAmzContentSHA256Mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Error {
    pub code: S3ErrorCode,
    pub message: String,
    pub resource: Option<String>,
    pub bucket_name: Option<String>,
    pub key: Option<String>,
    pub upload_id: Option<String>,
    pub extra_headers: Vec<(String, String)>,
}

impl S3Error {
    pub fn new(code: S3ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            resource: None,
            bucket_name: None,
            key: None,
            upload_id: None,
            extra_headers: Vec::new(),
        }
    }

    pub fn with_bucket(mut self, bucket: impl Into<String>) -> Self {
        let b = bucket.into();
        if self.resource.is_none() {
            self.resource = Some(format!("/{b}"));
        }
        self.bucket_name = Some(b);
        self
    }

    pub fn with_key(mut self, bucket: impl Into<String>, key: impl Into<String>) -> Self {
        let b = bucket.into();
        let k = key.into();
        self.resource = Some(format!("/{b}/{k}"));
        self.bucket_name = Some(b);
        self.key = Some(k);
        self
    }

    pub fn with_upload(
        mut self,
        bucket: impl Into<String>,
        key: impl Into<String>,
        upload_id: impl Into<String>,
    ) -> Self {
        let b = bucket.into();
        let k = key.into();
        let u = upload_id.into();
        self.resource = Some(format!("/{b}/{k}"));
        self.bucket_name = Some(b);
        self.key = Some(k);
        self.upload_id = Some(u);
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
        self
    }
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.code.as_str(), self.code.status_code(), self.message)
    }
}

impl std::error::Error for S3Error {}

pub type StoreResult<T> = Result<T, S3Error>;
