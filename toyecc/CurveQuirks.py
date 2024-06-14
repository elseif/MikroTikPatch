#
#	toyecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2022 Johannes Bauer
#
#	This file is part of toyecc.
#
#	toyecc is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	toyecc is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with toyecc; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#

import hashlib

class CurveQuirk(object):
	identifier = None

	@property
	def identity(self):
		return (self.identifier, )

	def __eq__(self, other):
		return self.identity == other.identity

	def __ne__(self, other):
		return not (self == other)

	def __lt__(self, other):
		return self.identity < other.identity

	def __hash__(self):
		return hash(self.identity)

	def __str__(self):
		return self.identifier

class CurveQuirkEdDSASetPrivateKeyMSB(CurveQuirk):
	"""Set the highest significant bit of the private key during EdDSA
	signature generation. For example, for EdDSA signatures on Ed25519, this
	would bitwise or the value 'a' with 2^254."""
	identifier = "EdDSA_set_private_key_MSB"

class CurveQuirkEdDSAEnsurePrimeOrderSubgroup(CurveQuirk):
	"""Ensures during EdDSA signature generation that the private key is on a
	prime-order subgroup. This is done by clearing the amount of bits that is
	required by the cofactor of the curve (which has to be a power of two for
	this quirk to work, otherwise it'll fail at runtime). Concretely, for EdDSA
	on Ed25519 this means that the least significant three bits would be set to
	zero because the curve cofactor is 8."""
	identifier = "EdDSA_use_prime_order_subgroup"

class CurveQuirkSigningHashFunction(CurveQuirk):
	"""For some curves, the signing hash function is implicitly given. In
	particular for the Ed448 and Ed25519 variants, this is true. Encode these
	as a curve quirk."""
	identifier = "signing_hash_function"

	def __init__(self, sig_fnc_name):
		self._sig_fnc_name = sig_fnc_name

	def hashdata(self, data):
		hash_fnc = {
			"sha512":			lambda x: hashlib.sha512(data).digest(),
			"shake256-114":		lambda x: hashlib.shake_256(data).digest(114),
		}
		return hash_fnc[self._sig_fnc_name](data)
