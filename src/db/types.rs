#[derive(Clone, Copy)]
pub enum VerificationStatus {
    Unverified = 0,
    Verified = 1,
    Locked = 2,
    Suspended = 3,
    OnDeletion = 4
}

impl PartialEq<i8> for VerificationStatus {
    fn eq(&self, other: &i8) -> bool {
        *self as i8 == *other
    }
}

impl Into<i8> for VerificationStatus {
    fn into(self) -> i8 {
        self as i8
    }
}

#[derive(Clone, Copy)]
pub enum ContactType {
    Personal = 0,
    Work = 1,
}

impl PartialEq<i8> for ContactType {
    fn eq(&self, other: &i8) -> bool {
        *self as i8 == *other
    }
}

impl Into<i8> for ContactType {
    fn into(self) -> i8 {
        self as i8
    }
}
