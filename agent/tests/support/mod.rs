//! Shared test scaffolding.
//!
//! Cargo compiles every file directly under `tests/` as its own test binary,
//! so helpers live one directory down and are pulled in as a module. Anything
//! here is compiled into each test binary that declares `mod support;`.

// Each test binary compiles the whole module and uses part of it, so what one
// binary leaves untouched another needs. `dead_code` here would mean "no
// single test uses all of it", which is the point of shared scaffolding
// rather than a finding about it.
#[allow(dead_code)]
pub mod mock_llm;
