//! Shared test scaffolding.
//!
//! Cargo compiles every file directly under `tests/` as its own test binary,
//! so helpers live one directory down and are pulled in as a module. Anything
//! here is compiled into each test binary that declares `mod support;`.

pub mod mock_llm;
