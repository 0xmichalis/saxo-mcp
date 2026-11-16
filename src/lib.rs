//! Read-only MCP server for the Saxo Bank OpenAPI.
//!
//! [`auth`] signs in with OAuth and keeps the session's tokens fresh; [`saxo`] is
//! a GET-only gateway client; [`mcp`] exposes it as MCP tools. No code path sends
//! anything but GET to the OpenAPI gateway, so the server cannot place, change or
//! cancel orders, whatever the session's token would allow.

pub mod auth;
pub mod config;
pub mod mcp;
pub mod saxo;
