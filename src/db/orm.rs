use std::collections::HashMap;
use charybdis::{
    macros::{charybdis_model, charybdis_udt_model, charybdis_view_model},
    scylla::SerializeValue,
    types::{Ascii, Blob, Boolean, Inet, Int, Map, SmallInt, Text, Timestamp},
};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use scylla::cql_to_rust::{FromCqlVal, FromCqlValError};
use scylla::frame::response::result::{ColumnType, CqlValue};
use scylla::serialize::{writers::WrittenCellProof, CellWriter, SerializationError};

#[charybdis_model(
    table_name = tenants,
    partition_keys = [tenant_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct Tenant {
    pub tenant_id: Ascii,
    pub name: Ascii,
    pub host: Ascii,
    pub created_at: Ascii
}

#[charybdis_view_model(
    table_name = tenants_by_host,
    base_table = tenants,
    partition_keys = [host],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct TenantByHost {
    pub tenant_id: Ascii,
    pub host: Ascii
}

#[charybdis_model(
    table_name = tenants_by_admin_user,
    partition_keys = [user_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct TenantByAdminUser {
    /// This user is from the main AccessCore tenant, so the tenant_id for this user is not
    /// required since it's already known.
    pub user_id: Ascii,

    /// The tenant administrated by this user.
    pub tenant_id: Ascii
}

#[charybdis_view_model(
    table_name = admin_users_by_tenant,
    base_table = tenants_by_admin_user,
    partition_keys = [tenant_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct AdminUserByTenant {
    /// This user is from the main AccessCore tenant, so the tenant_id for this user is not
    /// required since it's already known.
    pub user_id: Ascii,

    /// The tenant administrated by this user.
    pub tenant_id: Ascii
}

#[charybdis_model(
    table_name = oauth_providers,
    partition_keys = [tenant_id],
    clustering_keys = [provider],
)]
#[derive(Debug, Default)]
pub struct OAuthProvider {
    pub tenant_id: Ascii,
    pub provider: Ascii,
    pub client_id: Ascii,
    pub client_secret: Ascii,
    pub is_active: Boolean,
    pub metadata: Map<Text, Text>
}

#[charybdis_model(
    table_name = tenant_settings,
    partition_keys = [tenant_id],
    clustering_keys = [category, key]
)]
#[derive(Debug, Default)]
pub struct TenantSetting {
    pub tenant_id: Ascii,
    pub category: TenantSettingCategory,
    pub key: Ascii,
    pub value: Ascii,
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum TenantSettingCategory {
    #[default]
    Security,
}

impl SerializeValue for TenantSettingCategory {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i8).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for TenantSettingCategory {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i8, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i8(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}

#[charybdis_model(
    table_name = organizations,
    partition_keys = [tenant_id, organization_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct Organization {
    pub tenant_id: Ascii,
    pub organization_id: Ascii,
    pub name: Text,
    pub metadata: Map<Ascii, Ascii>
}

#[charybdis_model(
    table_name = organizations_by_user,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [organization_id]
)]
#[derive(Debug, Default)]
pub struct OrganizationByUser {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub organization_id: Ascii
}

#[charybdis_view_model(
    table_name = users_by_organization,
    base_table = organizations_by_user,
    partition_keys = [tenant_id, organization_id],
    clustering_keys = [user_id]
)]
#[derive(Debug, Default)]
pub struct UserByOrganization {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub organization_id: Ascii
}

#[charybdis_model(
    table_name = users,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [],
)]
#[derive(Debug, Default)]
pub struct User {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub username: Option<Text>,
    pub name: UserName,
    pub location: Option<Text>,
    pub locale: Ascii,
    pub can_access_tenant: Boolean,
    pub timezone: Ascii,
    pub status: UserStatus,
    pub roles: Vec<Text>,
    pub employment: UserEmployment,
    pub last_login: Option<Timestamp>,
    pub login_count: Int,
    pub metadata: HashMap<Ascii, Ascii>,
    pub permissions: Vec<Ascii>,
    pub password: Option<Ascii>,
    pub security_question_id: Option<SmallInt>,
    pub security_question_answer: Option<Ascii>,
    pub created_at: Timestamp,
    pub updated_at: Option<Timestamp>,
}

#[charybdis_udt_model(type_name = user_name)]
#[derive(Debug, Default)]
pub struct UserName {
    pub first: Option<Text>,
    pub middle: Option<Text>,
    pub last: Option<Text>,
    pub prefix: Option<Text>,
    pub suffix: Option<Text>,
}

#[charybdis_udt_model(type_name = user_employment)]
#[derive(Debug, Default)]
pub struct UserEmployment {
    pub title: Option<Text>,
    pub manager_id: Option<Ascii>,
    pub employee_number: Option<Int>,
    pub cost_center: Option<Text>,
    pub organization: Option<Text>,
    pub division: Option<Text>,
    pub department: Option<Text>
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum UserStatus {
    #[default]
    Unverified = 0,
    Active = 1,
    Locked = 2,
    Suspended = 3,
    OnDeletion = 4,
}

impl SerializeValue for UserStatus {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i8).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for UserStatus {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i8, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i8(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}

#[charybdis_view_model(
    table_name = users_by_username,
    base_table = users,
    partition_keys = [tenant_id, username],
    clustering_keys = [user_id]
)]
#[derive(Debug, Default)]
pub struct UserByUsername {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub username: Text,
}

#[charybdis_model(
    table_name = emails,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [],
)]
#[derive(Debug, Default)]
pub struct Email {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub email: Text,
    pub is_main: Boolean,
    pub is_work: Boolean,
    pub is_verified: Boolean,
    pub created_at: Timestamp,
    pub verified_at: Option<Timestamp>
}

#[charybdis_view_model(
    table_name = users_by_email,
    base_table = emails,
    partition_keys = [tenant_id, email],
    clustering_keys = [user_id]
)]
#[derive(Debug, Default)]
pub struct UserByEmail {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub email: Text,
}

#[charybdis_model(
    table_name = phone_numbers,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [],
)]
#[derive(Debug, Default)]
pub struct PhoneNumber {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub number: Text,
    pub is_main: Boolean,
    pub is_work: Boolean,
    pub is_verified: Boolean,
    pub created_at: Timestamp,
    pub verified_at: Option<Timestamp>
}

#[charybdis_view_model(
    table_name = users_by_phone_number,
    base_table = phone_numbers,
    partition_keys = [tenant_id, number],
    clustering_keys = [user_id]
)]
#[derive(Debug, Default)]
pub struct UserByPhoneNumber {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub number: Text,
}

#[charybdis_model(
    table_name = oauth_accounts,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [provider, external_id],
)]
#[derive(Debug, Default)]
pub struct OAuthAccount {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub provider: Ascii,
    pub external_id: Ascii,
    
    /// The name of the external account. E.g. if in Discord your username is "nyeki.py", this
    /// property will contain that.
    pub name: Text,
    pub access_token: Ascii,
    pub refresh_token: Ascii,
    pub access_token_expires_at: Timestamp,
    pub refresh_token_expires_at: Timestamp,
    pub scopes: Vec<Ascii>,
    
    /// If not, it requires a re-login
    pub is_active: Boolean,
}

#[charybdis_view_model(
    table_name = users_by_oauth_account,
    base_table = oauth_accounts,
    partition_keys = [tenant_id, provider, external_id],
    clustering_keys = [user_id]
)]
#[derive(Debug, Default)]
pub struct UserByOAuthAccount {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub provider: Ascii,
    pub external_id: Ascii,
}

#[charybdis_model(
    table_name = mfa_codes,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [code_type, code],

    // Default TTL: 15 minutes
    table_options = r#"
        default_time_to_live = 900
    "#
)]
pub struct MFACode {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub code: Int,
    pub code_type: MFACodeType,
    pub created_at: Timestamp
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum MFACodeType {
    #[default]
    Email = 0,
    SMS = 1,
    Whatsapp = 2,
    PushNotification = 3,
}

impl SerializeValue for MFACodeType {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i8).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for MFACodeType {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i8, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i8(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}

// TODO: Rename struct to "OldPassword"?
#[charybdis_model(
    table_name = passwords,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [],
    
    // Default TTL: 6 months
    table_options = r#"
        default_time_to_live = 15811200
    "#
)]
#[derive(Debug, Default)]
pub struct Password {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub hash: Ascii,
    pub changed_at: Timestamp,
}

#[charybdis_model(
    table_name = devices,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [device_id],
)]
#[derive(Debug, Default)]
pub struct Device {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub device_id: Ascii,
    pub os: Option<Ascii>,
    pub os_version: Option<Ascii>,
    pub family: Option<Ascii>,
    pub brand: Option<Ascii>,
    pub model: Option<Ascii>,
    pub client_id: Option<Ascii>,
    pub ip: Option<Inet>,
    pub location: Option<Text>,
    pub created_at: Timestamp,
    pub last_login: Option<Timestamp>
}

#[charybdis_model(
    table_name = api_tokens,
    partition_keys = [tenant_id, token],
    clustering_keys = [user_id],

    // Default TTL: 1 month.
    table_options = r#"
        default_time_to_live = 2592000
    "#
)]
#[derive(Debug, Default)]
pub struct APIToken {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub token: Blob,
    pub is_refresh: Boolean,
    pub scopes: Vec<Ascii>,
    pub device_id: Option<Ascii>,
    pub client_id: Option<Ascii>
}

#[charybdis_model(
    table_name = api_clients,
    partition_keys = [tenant_id, client_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct APIClient {
    pub tenant_id: Ascii,
    pub client_id: Ascii,
    pub secret: Option<Ascii>,
    pub name: Text,
    pub client_type: APIClientType,
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum APIClientType {
    #[default]
    Internal = 0,
    Web = 1,
    Desktop = 2,
    Mobile = 3,
    Console = 4,
    IOT = 5
}

impl SerializeValue for APIClientType {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i8).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for APIClientType {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i8, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i8(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}

#[charybdis_model(
    table_name = groups,
    partition_keys = [tenant_id, group_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct Group {
    pub tenant_id: Ascii,
    pub group_id: Ascii,
    pub name: Text,
    pub description: Option<Text>,
    pub permissions: Vec<Ascii>,
    pub priority: SmallInt,
    pub color: Option<Int>
}

#[charybdis_model(
    table_name = users_by_group,
    partition_keys = [tenant_id, group_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct UserByGroup {
    pub tenant_id: Ascii,
    pub group_id: Ascii,
    pub user_id: Ascii
}

#[charybdis_view_model(
    table_name = groups_by_user,
    base_table = users_by_group,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [group_id]
)]
#[derive(Debug, Default)]
pub struct GroupByUser {
    pub tenant_id: Ascii,
    pub group_id: Ascii,
    pub user_id: Ascii
}

#[charybdis_model(
    table_name = activity_logs,
    partition_keys = [tenant_id, user_id],
    clustering_keys = []
)]
#[derive(Debug, Default)]
pub struct ActivityLog {
    pub tenant_id: Ascii,
    pub user_id: Ascii,
    pub request_id: Ascii,
    pub data: Ascii,
    pub timestamp: Timestamp
}

#[charybdis_model(
    table_name = notification_recipients,
    partition_keys = [tenant_id, user_id],
    clustering_keys = [notification_id],

    // Default TTL: 3 months.
    table_options = r#"
        default_time_to_live = 7776000
    "#
)]
#[derive(Debug, Default)]
pub struct NotificationRecipient {
    pub tenant_id: Ascii,
    pub notification_id: Ascii,
    pub user_id: Ascii,
    pub status: NotificationStatus,
    pub sent_at: Option<Timestamp>,
    pub read_at: Option<Timestamp>,
    pub notification_type: NotificationType
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum NotificationStatus {
    #[default]
    Pending,
    Sent,
    Read,
    Failed
}

impl SerializeValue for NotificationStatus {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i8).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for NotificationStatus {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i8, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i8(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum NotificationType {
    #[default]
    InApp,
    Whatsapp,
    Email,
    SMS,
    Push
}

impl SerializeValue for NotificationType {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i8).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for NotificationType {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i8, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i8(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}

#[charybdis_model(
    table_name = notifications,
    partition_keys = [tenant_id, notification_id],
    clustering_keys = [],

    // Default TTL: 3 months.
    table_options = r#"
        default_time_to_live = 7776000
    "#
)]
#[derive(Debug, Default)]
pub struct Notification {
    pub tenant_id: Ascii,
    pub notification_id: Ascii,
    pub event: NotificationEvent,
    pub title: Text,
    pub message: Text,
    pub data: Map<Text, Text>,
    pub priority: NotificationPriority,
    pub created_at: Timestamp
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum NotificationEvent {
    #[default]
    AdminMessage,
}

impl SerializeValue for NotificationEvent {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i32).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for NotificationEvent {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i32, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i32(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}

#[derive(Clone, Copy, FromPrimitive, Debug, Default)]
pub enum NotificationPriority {
    #[default]
    Low,
    Medium,
    High,
    Critical
}

impl SerializeValue for NotificationPriority {
    fn serialize<'b>(
        &self,
        typ: &ColumnType,
        writer: CellWriter<'b>,
    ) -> Result<WrittenCellProof<'b>, SerializationError> {
        (*self as i32).serialize(typ, writer)
    }
}

impl FromCqlVal<CqlValue> for NotificationPriority {
    fn from_cql(cql_val: CqlValue) -> Result<Self, FromCqlValError> {
        let raw_val: Result<i32, FromCqlValError> = FromCqlVal::<CqlValue>::from_cql(cql_val);
        raw_val.and_then(|v| match FromPrimitive::from_i32(v) {
            Some(e) => Ok(e),
            None => Err(FromCqlValError::BadVal),
        })
    }
}
