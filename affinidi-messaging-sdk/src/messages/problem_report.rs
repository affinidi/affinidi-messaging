//! DIDComm Problem Report handling
//! [https://identity.foundation/didcomm-messaging/spec/#problem-reports]
//!
use core::fmt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProblemReport {
    pub code: String,
    pub comment: String,
    pub args: Vec<String>,
    #[serde(rename = "escalate_to")]
    pub escalate_to: Option<String>,
}

/// DIDComm Problem Report Sorter Code
/// - `Error` - Error, a clear failure to achieve goal)
/// - `Warning` - Warning, may be a problem - up to the receiver to decide.
#[derive(Serialize, Deserialize)]
pub enum ProblemReportSorter {
    Error,
    Warning,
}

impl fmt::Display for ProblemReportSorter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProblemReportSorter::Error => write!(f, "e"),
            ProblemReportSorter::Warning => write!(f, "w"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum ProblemReportScope {
    Protocol,
    Message,
    Other(String),
}

impl fmt::Display for ProblemReportScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProblemReportScope::Protocol => write!(f, "p"),
            ProblemReportScope::Message => write!(f, "m"),
            ProblemReportScope::Other(ref s) => write!(f, "{}", s),
        }
    }
}

impl ProblemReport {
    /// Create a new Problem Report
    /// - `sorter` - The sorter code (Problem or Warning?)
    /// - `scope` - The scope code (Protocol, Message, or Other)
    /// - `descriptor` - The descriptor code (e.g. `trust.crypto` = Cryptographic operation failed)
    /// - `comment` - A human-readable comment (arguments must be in {1} {2} {n} format)
    /// - `args` - Arguments to the comment
    ///
    /// Example:
    /// let comment = "authentication for {1} failed due to {2}";
    /// let args = vec!["Alice".to_string(), "invalid signature".to_string()];
    pub fn new(
        sorter: ProblemReportSorter,
        scope: ProblemReportScope,
        descriptor: String,
        comment: String,
        args: Vec<String>,
        escalate_to: Option<String>,
    ) -> Self {
        ProblemReport {
            code: format!("{}.{}.{}", sorter, scope, descriptor),
            comment,
            args,
            escalate_to,
        }
    }
}

mod tests {
    #[cfg(test)]
    use crate::messages::problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter};

    #[test]
    fn test_problem_report() {
        let comment = "authentication for {1} failed due to {2}";
        let args = vec!["Alice".to_string(), "invalid signature".to_string()];
        let problem_report = ProblemReport::new(
            ProblemReportSorter::Error,
            ProblemReportScope::Other("test".to_string()),
            "authentication".to_string(),
            comment.to_string(),
            args.clone(),
            None,
        );

        assert_eq!(problem_report.code, "e.test.authentication");
        assert_eq!(problem_report.comment, comment);
        assert_eq!(problem_report.args, args);
    }
}
