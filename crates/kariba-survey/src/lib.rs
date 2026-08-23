pub mod clamav;
pub mod report;

use kariba_core::{detect_distro, detect_init};
pub use report::{CheckResult, CheckStatus, SurveyReport};

pub fn run_survey() -> SurveyReport {
    let distro = detect_distro();
    let init = detect_init();
    let mut checks = Vec::new();
    checks.extend(clamav::check(&distro, init));
    SurveyReport {
        distro,
        init,
        checks,
    }
}
