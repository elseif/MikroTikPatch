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

from .PrivKeyOps import PrivKeyOpECDSASign, PrivKeyOpECIESDecrypt, PrivKeyOpEDDSASign, PrivKeyOpEDDSAKeyGen, PrivKeyOpEDDSAEncode, PrivKeyOpECDH, PrivKeyOpLoad
from .ECPublicKey import ECPublicKey
from .Random import secure_rand_int_between

class ECPrivateKey(PrivKeyOpECDSASign, PrivKeyOpECIESDecrypt, PrivKeyOpEDDSASign, PrivKeyOpEDDSAKeyGen, PrivKeyOpEDDSAEncode, PrivKeyOpECDH, PrivKeyOpLoad):
	"""Represents an elliptic curve private key."""

	def __init__(self, scalar, curve):
		"""Initialize the private key with the given scalar on the given
		curve."""
		self._seed = None
		self._scalar = scalar
		self._curve = curve
		self._pubkey = ECPublicKey(self._scalar * self._curve.G)

	@property
	def scalar(self):
		"""Returns the private scalar d of the key."""
		return self._scalar

	@property
	def curve(self):
		"""Returns the group which is used for EC computations."""
		return self._curve

	@property
	def pubkey(self):
		"""Returns the public key that is the counterpart to this private key."""
		return self._pubkey

	@property
	def seed(self):
		"""Returns the seed or None if there wasn't one. A seed is used for
		schemes like EdDSA; it basically is a binary string that is hashed to
		yield that actual private scalar d."""
		return self._seed

	def set_seed(self, seed):
		"""Sets the seed of the private key. This operation can only performed
		if no scalar has previously been set for this key."""
		assert(self._seed is None)
		self._seed = seed
		return self

	@staticmethod
	def generate(curve):
		"""Generate a random private key on a given curve."""
		scalar = secure_rand_int_between(1, curve.n - 1)
		return ECPrivateKey(scalar, curve)

	def __str__(self):
		if self._seed is None:
			return "PrivateKey<d = 0x%x>" % (self.scalar)
		else:
			seedstr = "".join("%02x" % (c) for c in self._seed)
			return "PrivateKey<d = 0x%x, seed = %s>" % (self.scalar, seedstr)
