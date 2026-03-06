//! Protocol types, codec, handler trait, and client for the Trustless key provider protocol.
//!
//! This crate implements the communication protocol between the Trustless proxy and
//! key provider processes. Key providers hold TLS private keys and perform signing
//! operations on behalf of the proxy, communicating over stdin/stdout with
//! length-delimited JSON messages.
//!
//! # For key provider implementors
//!
//! Implement the [`handler::Handler`] trait and call [`handler::run`] to start
//! the event loop. See `trustless-provider-stub` for a complete example.
//!
//! # For proxy internals
//!
//! Use [`client::ProviderClient`] to communicate with a spawned provider process.

/// Async client for communicating with a key provider process.
pub mod client;
/// Length-delimited codec for framing and serializing messages.
pub mod codec;
/// Error types for protocol operations.
pub mod error;
/// Handler trait and event loop for implementing key providers.
pub mod handler;
/// Protocol message types (requests, responses, parameters, results).
pub mod message;
/// Signature scheme name parsing and algorithm mapping.
pub mod scheme;
