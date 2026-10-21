//! These days, there are several possible ways to communicate Bitcoin receive instructions.
//!
//! This module attempts to unify them into a simple parser which can read text provided directly
//! by a receiver or via a QR code scan/URI open and convert it into receive instructions.
//!
//! See the [`ReceiveInstructions`] type for the supported instruction formats.
//!
//! This module doesn't actually help you *receive* these funds, but provides a unified way to
//! parse them.

use bitcoin::secp256k1::SecretKey;
use bitcoin::Network;

use lightning::offers::parse::Bolt12ParseError;
use lightning::offers::refund::Refund;

use alloc::str::FromStr;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use core::time::Duration;

/// A method which can be used to receive a payment
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ReceiveMethod {
	/// A raw bitcoin private key, this will be parsed WIF encoded
	PrivateKey(SecretKey),
	/// A Bolt 12 Refund
	Bolt12Refund(Refund),
	// TODO: lnurl withdrawal? (sadly, cannot be identified as such statically...)
}

/// An error when parsing payment instructions into [`ReceiveInstructions`].
#[derive(Debug)]
pub enum ParseError {
	/// An invalid lightning BOLT 12 refund was encountered
	InvalidBolt12(Bolt12ParseError),
	/// The receive instructions encoded instructions for a network other than the one specified.
	WrongNetwork,
	/// The instructions were invalid due to a semantic error.
	///
	/// A developer-readable error string is provided, though you may or may not wish to provide
	/// this directly to users.
	InvalidInstructions(&'static str),
	/// The receive instructions did not appear to match any known form of receive instructions.
	UnknownReceiveInstructions,
	/// The BIP 321 bitcoin: URI included unknown required parameter(s)
	UnknownRequiredParameter,
	/// The payment instructions have expired and are no longer payable.
	InstructionsExpired,
}

pub(crate) fn check_expiry(_expiry: Duration) -> Result<(), ParseError> {
	#[cfg(feature = "std")]
	{
		use std::time::SystemTime;
		if let Ok(now) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
			if now > _expiry {
				return Err(ParseError::InstructionsExpired);
			}
		}
	}
	Ok(())
}

/// Parsed receive instructions representing a set of possible ways to receive, as well as an
/// associated description.
///
/// It supports:
///  * Raw WIF encoded private keys (which should be swept)
///  * Lightning Bolt 12 Refunds
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ReceiveInstructions {
	description: Option<String>,
	methods: Vec<ReceiveMethod>,
}

impl ReceiveInstructions {
	/// The list of [`ReceiveMethod`]s.
	pub fn methods(&self) -> &[ReceiveMethod] {
		&self.methods
	}

	/// A sender-provided description of the payment instructions.
	///
	/// This may be:
	///  * the `description` field in a lightning BOLT 12 offer
	pub fn sender_description(&self) -> Option<&str> {
		self.description.as_deref()
	}

	/// Resolves a string into [`ReceiveInstructions`]. Verifying it is valid for the given network
	pub fn parse_receive_instructions(
		instructions: &str, network: Network,
	) -> Result<ReceiveInstructions, ParseError> {
		if instructions.is_empty() {
			return Err(ParseError::InvalidInstructions("Empty string"));
		}
		const BTC_URI_PFX_LEN: usize = "bitcoin:".len();

		// TODO this is copied from `parse_resolved_instructions` could refactor into unified function potentially
		// we don't check for WIF encoded private keys in bitcoin: qr codes because that is not really something
		// anyone does, nor does it make sense in its context
		if instructions.len() >= BTC_URI_PFX_LEN
			&& instructions[..BTC_URI_PFX_LEN].eq_ignore_ascii_case("bitcoin:")
		{
			let uri = bitcoin_uri::Uri::parse(instructions)
				.map_err(|_| ParseError::InvalidInstructions("Invalid BIP 321 bitcoin: URI"))?;
			if uri.unsatisfied_requirements(&["lnr"]).next().is_some() {
				return Err(ParseError::UnknownRequiredParameter);
			}
			let mut methods = Vec::new();
			let mut description = None;
			// `get_all` matches `req-lnr` as well as `lnr`.
			for param in uri.get_all("lnr") {
				if let Some(v) = param.decoded_value() {
					let v = v.map_err(|_| {
						let err = "A BOLT 12 refund parameter in a BIP 321 bitcoin: URI was not valid percent-encoded UTF-8";
						ParseError::InvalidInstructions(err)
					})?;
					match Refund::from_str(&v) {
						Ok(refund) => {
							if refund.chain() != network.chain_hash() {
								return Err(ParseError::WrongNetwork);
							}

							description = Some(refund.description().0.to_string());
							methods.push(ReceiveMethod::Bolt12Refund(refund));
						},
						Err(err) => return Err(ParseError::InvalidBolt12(err)),
					}
				} else {
					let err =
						"Missing value for a BOLT 12 refund parameter in a BIP 321 bitcoin: URI";
					return Err(ParseError::InvalidInstructions(err));
				}
			}

			if methods.is_empty() {
				return Err(ParseError::UnknownReceiveInstructions);
			}

			return Ok(ReceiveInstructions { description, methods });
		}

		if let Ok(pk) = bitcoin::key::PrivateKey::from_wif(instructions) {
			if pk.network != network.into() {
				return Err(ParseError::WrongNetwork);
			}

			return Ok(ReceiveInstructions {
				description: None,
				methods: vec![ReceiveMethod::PrivateKey(pk.inner)],
			});
		}

		if let Ok(refund) = Refund::from_str(instructions) {
			if refund.chain() != network.chain_hash() {
				return Err(ParseError::WrongNetwork);
			}
			if let Some(expiry) = refund.absolute_expiry() {
				check_expiry(expiry)?;
			}

			return Ok(ReceiveInstructions {
				description: Some(refund.description().to_string()),
				methods: vec![ReceiveMethod::Bolt12Refund(refund)],
			});
		}

		Err(ParseError::UnknownReceiveInstructions)
	}
}
