use serde::{Deserialize, Serialize};

use crate::error::{S3Error, S3ErrorCode, StoreResult};
use crate::store::{ObjectOwnership, OwnerInfo};

pub const GROUP_ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
pub const GROUP_AUTHENTICATED_USERS: &str =
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";
pub const GROUP_LOG_DELIVERY: &str = "http://acs.amazonaws.com/groups/s3/LogDelivery";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclPermission {
    Read,
    Write,
    ReadAcp,
    WriteAcp,
    FullControl,
}

impl AclPermission {
    pub const fn as_aws_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::ReadAcp => "READ_ACP",
            Self::WriteAcp => "WRITE_ACP",
            Self::FullControl => "FULL_CONTROL",
        }
    }

    pub fn from_aws_str(s: &str) -> Option<Self> {
        match s.trim() {
            "READ" => Some(Self::Read),
            "WRITE" => Some(Self::Write),
            "READ_ACP" => Some(Self::ReadAcp),
            "WRITE_ACP" => Some(Self::WriteAcp),
            "FULL_CONTROL" => Some(Self::FullControl),
            _ => None,
        }
    }

    pub const fn satisfies(self, needed: Self) -> bool {
        matches!(
            (self, needed),
            (Self::FullControl, _)
                | (Self::Read, Self::Read)
                | (Self::Write, Self::Write)
                | (Self::ReadAcp, Self::ReadAcp)
                | (Self::WriteAcp, Self::WriteAcp)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclGrantee {
    CanonicalUser(OwnerInfo),
    Group(String),
}

impl AclGrantee {
    pub fn is_public_group(&self) -> bool {
        matches!(
            self,
            Self::Group(u) if u == GROUP_ALL_USERS || u == GROUP_AUTHENTICATED_USERS
        )
    }

    pub fn matches_caller(&self, caller: Option<&OwnerInfo>, is_authenticated: bool) -> bool {
        match self {
            Self::CanonicalUser(target) => caller.is_some_and(|c| c.user_id == target.user_id),
            Self::Group(uri) => {
                if uri == GROUP_ALL_USERS {
                    true
                } else if uri == GROUP_AUTHENTICATED_USERS {
                    is_authenticated
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclGrant {
    pub grantee: AclGrantee,
    pub permission: AclPermission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessControlPolicy {
    pub owner: OwnerInfo,
    pub grants: Vec<AclGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CannedAcl {
    Private,
    PublicRead,
    PublicReadWrite,
    AuthenticatedRead,
    AwsExecRead,
    BucketOwnerRead,
    BucketOwnerFullControl,
    LogDeliveryWrite,
}

impl CannedAcl {
    pub fn from_aws_str(s: &str) -> Option<Self> {
        match s.trim() {
            "private" => Some(Self::Private),
            "public-read" => Some(Self::PublicRead),
            "public-read-write" => Some(Self::PublicReadWrite),
            "authenticated-read" => Some(Self::AuthenticatedRead),
            "aws-exec-read" => Some(Self::AwsExecRead),
            "bucket-owner-read" => Some(Self::BucketOwnerRead),
            "bucket-owner-full-control" => Some(Self::BucketOwnerFullControl),
            "log-delivery-write" => Some(Self::LogDeliveryWrite),
            _ => None,
        }
    }

    pub const fn is_public(self) -> bool {
        matches!(
            self,
            Self::PublicRead | Self::PublicReadWrite | Self::AuthenticatedRead
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclSpec {
    Canned(CannedAcl),
    Grants(Vec<AclGrant>),
    Policy(AccessControlPolicy),
}

impl AccessControlPolicy {
    pub fn new_private(owner: OwnerInfo) -> Self {
        let g_owner = owner.clone();
        Self {
            owner,
            grants: vec![AclGrant {
                grantee: AclGrantee::CanonicalUser(g_owner),
                permission: AclPermission::FullControl,
            }],
        }
    }

    pub fn from_canned(
        canned: CannedAcl,
        resource_owner: &OwnerInfo,
        bucket_owner: Option<&OwnerInfo>,
    ) -> Self {
        let owner_grant = AclGrant {
            grantee: AclGrantee::CanonicalUser(resource_owner.clone()),
            permission: AclPermission::FullControl,
        };
        let mut grants = Vec::with_capacity(3);
        match canned {
            CannedAcl::Private | CannedAcl::AwsExecRead => {
                grants.push(owner_grant);
            }
            CannedAcl::PublicRead => {
                grants.push(AclGrant {
                    grantee: AclGrantee::Group(GROUP_ALL_USERS.to_string()),
                    permission: AclPermission::Read,
                });
                grants.push(owner_grant);
            }
            CannedAcl::PublicReadWrite => {
                grants.push(AclGrant {
                    grantee: AclGrantee::Group(GROUP_ALL_USERS.to_string()),
                    permission: AclPermission::Read,
                });
                grants.push(AclGrant {
                    grantee: AclGrantee::Group(GROUP_ALL_USERS.to_string()),
                    permission: AclPermission::Write,
                });
                grants.push(owner_grant);
            }
            CannedAcl::AuthenticatedRead => {
                grants.push(AclGrant {
                    grantee: AclGrantee::Group(GROUP_AUTHENTICATED_USERS.to_string()),
                    permission: AclPermission::Read,
                });
                grants.push(owner_grant);
            }
            CannedAcl::BucketOwnerRead => {
                grants.push(owner_grant);
                if let Some(bo) = bucket_owner
                    && bo.user_id != resource_owner.user_id {
                        grants.push(AclGrant {
                            grantee: AclGrantee::CanonicalUser(bo.clone()),
                            permission: AclPermission::Read,
                        });
                    }
            }
            CannedAcl::BucketOwnerFullControl => {
                grants.push(owner_grant);
                if let Some(bo) = bucket_owner
                    && bo.user_id != resource_owner.user_id {
                        grants.push(AclGrant {
                            grantee: AclGrantee::CanonicalUser(bo.clone()),
                            permission: AclPermission::FullControl,
                        });
                    }
            }
            CannedAcl::LogDeliveryWrite => {
                grants.push(AclGrant {
                    grantee: AclGrantee::Group(GROUP_LOG_DELIVERY.to_string()),
                    permission: AclPermission::Write,
                });
                grants.push(AclGrant {
                    grantee: AclGrantee::Group(GROUP_LOG_DELIVERY.to_string()),
                    permission: AclPermission::ReadAcp,
                });
                grants.push(owner_grant);
            }
        }
        Self {
            owner: resource_owner.clone(),
            grants,
        }
    }

    pub fn has_public_grants(&self) -> bool {
        self.grants.iter().any(|g| g.grantee.is_public_group())
    }

    pub fn is_default_private_for(&self, owner: &OwnerInfo) -> bool {
        self.owner.user_id == owner.user_id
            && self.grants.iter().all(|g| {
                matches!(&g.grantee, AclGrantee::CanonicalUser(u) if u.user_id == owner.user_id)
            })
    }

    pub fn allows(
        &self,
        caller: Option<&OwnerInfo>,
        is_authenticated: bool,
        needed: AclPermission,
        ignore_public_acls: bool,
    ) -> bool {
        for grant in &self.grants {
            if ignore_public_acls && grant.grantee.is_public_group() {
                continue;
            }
            if grant.permission.satisfies(needed)
                && grant.grantee.matches_caller(caller, is_authenticated)
            {
                return true;
            }
        }
        false
    }
}

/// Resolve effective object owner & ACL on object creation (`PutObject`, `CopyObject`, `CreateMultipartUpload`) per `PR-31` & `PR-32`.
pub fn resolve_object_owner_and_acl(
    ownership: ObjectOwnership,
    bucket_owner: &OwnerInfo,
    caller: Option<&OwnerInfo>,
    acl_spec: Option<&AclSpec>,
) -> StoreResult<(OwnerInfo, AccessControlPolicy)> {
    if ownership == ObjectOwnership::BucketOwnerEnforced {
        if let Some(spec) = acl_spec {
            match spec {
                AclSpec::Canned(CannedAcl::BucketOwnerFullControl) => {}
                _ => {
                    return Err(S3Error::new(
                        S3ErrorCode::AccessControlListNotSupported,
                        "The bucket does not allow ACLs",
                    ));
                }
            }
        }
        let owner = bucket_owner.clone();
        let acl = AccessControlPolicy::new_private(owner.clone());
        return Ok((owner, acl));
    }

    let uploader = caller.unwrap_or(bucket_owner);
    let effective_owner = if ownership == ObjectOwnership::BucketOwnerPreferred
        && matches!(acl_spec, Some(AclSpec::Canned(CannedAcl::BucketOwnerFullControl)))
    {
        bucket_owner.clone()
    } else {
        uploader.clone()
    };

    let acl = match acl_spec {
        None => AccessControlPolicy::new_private(effective_owner.clone()),
        Some(spec) => resolve_target_acl(&effective_owner, Some(bucket_owner), spec)?,
    };
    Ok((effective_owner, acl))
}

/// Resolve an `AclSpec` against an existing `resource_owner` (used by `CreateBucket`, `PutBucketAcl`, `PutObjectAcl`).
pub fn resolve_target_acl(
    resource_owner: &OwnerInfo,
    bucket_owner: Option<&OwnerInfo>,
    spec: &AclSpec,
) -> StoreResult<AccessControlPolicy> {
    match spec {
        AclSpec::Canned(c) => Ok(AccessControlPolicy::from_canned(
            *c,
            resource_owner,
            bucket_owner,
        )),
        AclSpec::Grants(grants) => {
            let mut grants = grants.clone();
            grants.sort_by_key(|g| matches!(g.grantee, AclGrantee::CanonicalUser(_)));
            Ok(AccessControlPolicy {
                owner: resource_owner.clone(),
                grants,
            })
        }
        AclSpec::Policy(pol) => {
            if pol.owner.user_id != resource_owner.user_id {
                return Err(S3Error::new(S3ErrorCode::InvalidArgument, "Invalid id"));
            }
            let mut grants = pol.grants.clone();
            grants.sort_by_key(|g| matches!(g.grantee, AclGrantee::CanonicalUser(_)));
            Ok(AccessControlPolicy {
                owner: resource_owner.clone(),
                grants,
            })
        }
    }
}
