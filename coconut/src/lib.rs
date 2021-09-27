#[macro_use]
mod error;
pub mod issue;
pub mod lagrange;
pub mod request;
pub mod setup;

#[cfg(test)]
#[path = "tests/fixtures.rs"]
mod fixtures;

#[cfg(test)]
#[path = "tests/integration_tests.rs"]
mod integration_tests;
