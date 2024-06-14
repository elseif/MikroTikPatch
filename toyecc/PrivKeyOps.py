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
import collections

from .FieldElement import FieldElement
from .Random import secure_rand, secure_rand_int_between
from .AffineCurvePoint import AffineCurvePoint
from .CurveDB import CurveDB
from .ShortWeierstrassCurve import ShortWeierstrassCurve
from .ASN1 import parse_asn1_private_key, parse_asn1_field_params_fp
from . import Tools
from .CurveQuirks import CurveQuirkEdDSASetPrivateKeyMSB, CurveQuirkEdDSAEnsurePrimeOrderSubgroup, CurveQuirkSigningHashFunction

class PrivKeyOpECDSASign(object):
	ECDSASignature = collections.namedtuple("ECDSASignature", [ "hashalg", "r", "s" ])

	def ecdsa_sign_hash(self, message_digest, k = None, digestname = None):
		"""Signs a given messagedigest, given as bytes, using ECDSA.
		Optionally a nonce k can be supplied which should usually be unqiuely
		chosen for every ECDSA signature. This way it is possible to
		deliberately create broken signatures which can be exploited later on.
		If k is not supplied, it is randomly chosen. If a digestname is
		supplied the name of this digest eventually ends up in the
		ECDSASignature object."""
		assert(isinstance(message_digest, bytes))
		assert((k is None) or isinstance(k, int))

		# Convert message digest to integer value
		e = Tools.ecdsa_msgdigest_to_int(message_digest, self.curve.n)

		# Select a random integer (if None is supplied!)
		if k is None:
			k = secure_rand_int_between(1, self.curve.n - 1)

		# r = (k * G)_x mod n
		Rmodp = k * self.curve.G
		r = int(Rmodp.x) % self.curve.n
		assert(r != 0)

		s = FieldElement(e + self.scalar * r, self.curve.n) // k

		return self.ECDSASignature(r = r, s = int(s), hashalg = digestname)

	def ecdsa_sign(self, message, digestname, k = None):
		"""Signs a given message with the digest that is given as a string.
		Optionally a nonce k can be supplied which should usually be unqiuely
		chosen for every ECDSA signature. This way it is possible to
		deliberately create broken signatures which can be exploited later
		on. If k is not supplied, it is randomly chosen."""
		assert(isinstance(message, bytes))
		assert(isinstance(digestname, str))
		digest_fnc = hashlib.new(digestname)
		digest_fnc.update(message)
		message_digest = digest_fnc.digest()
		return self.ecdsa_sign_hash(message_digest, k = k, digestname = digestname)


class PrivKeyOpECIESDecrypt(object):
	def ecies_decrypt(self, R):
		"""Takes the transmitted point R and reconstructs the shared secret
		point S using the private key."""
		# Transmitted R is given, restore the symmetric key S
		return self._scalar * R


class PrivKeyOpEDDSASign(object):
	class EDDSASignature(object):
		def __init__(self, curve, R, s):
			self._curve = curve
			self._R = R
			self._s = s

		@property
		def curve(self):
			return self._curve

		@property
		def R(self):
			return self._R

		@property
		def s(self):
			return self._s

		def encode(self):
			"""Performs serialization of the signature as used by EdDSA."""
			return self.R.eddsa_encode() + Tools.inttobytes_le(self.s, (self.curve.B + 7) // 8)

		@classmethod
		def decode(cls, curve, encoded_signature):
			"""Performs deserialization of the signature as used by EdDSA."""
			assert(isinstance(encoded_signature, bytes))
			coordlen = (curve.B + 7) // 8
			assert(len(encoded_signature) == 2 * coordlen)
			encoded_R = encoded_signature[:coordlen]
			encoded_s = encoded_signature[coordlen:]
			R = AffineCurvePoint.eddsa_decode(curve, encoded_R)
			s = Tools.bytestoint_le(encoded_s)
			return cls(curve, R, s)

		def __eq__(self, other):
			return (self.R, self.s) == (other.R, other.s)

		def __str__(self):
			return "EDDSASignature<R = %s, s = %s>" % (self.R, self.s)

	def eddsa_sign(self, message):
		"""Performs an EdDSA signature of the message. For this to work the
		curve has to be a twisted Edwards curve and the private key scalar has
		to be generated from a hashed seed. This hashed seed is automatically
		generated when a keypair is generated using, for example, the
		eddsa_generate() function instead of the regular key generation
		function generate()."""
		assert(self.curve.curvetype == "twistededwards")
		if self._seed is None:
			raise Exception("EdDSA requires a seed which is the source for calculation of the private key scalar.")
		if not self.curve.has_quirk(CurveQuirkSigningHashFunction):
			raise Exception("Unable to determine EdDSA signature function.")

		quirk = self.curve.get_quirk(CurveQuirkSigningHashFunction)
		h = quirk.hashdata(self._seed)

		coordlen = (self.curve.B + 7) // 8
		r = Tools.bytestoint_le(quirk.hashdata(h[coordlen : 2 * coordlen] + message))
		R = r * self.curve.G
		s = (r + Tools.bytestoint_le(quirk.hashdata(R.eddsa_encode() + self.pubkey.point.eddsa_encode() + message)) * self.scalar) % self.curve.n
		sig = self.EDDSASignature(self.curve, R, s)
		return sig


class PrivKeyOpEDDSAKeyGen(object):
	@classmethod
	def eddsa_generate(cls, curve, seed = None):
		"""Generates a randomly selected seed value. This seed value is then
		hashed using the EdDSA hash function (SHA512 for Ed2556 and
		Shake256-114 for Ed448) and the resulting value is (slightly modified)
		used as the private key scalar.  Since for EdDSA signing operations
		this seed value is needed, it is also stored within the private key."""
		coordlen = (curve.B + 7) // 8
		if seed is None:
			seed = secure_rand(coordlen)
		assert(isinstance(seed, bytes))
		assert(len(seed) == coordlen)

		# Calculate hash over seed and generate scalar from hash over seed
		if not curve.has_quirk(CurveQuirkSigningHashFunction):
			raise Exception("Unable to determine EdDSA signature function.")
		quirk = curve.get_quirk(CurveQuirkSigningHashFunction)
		h = quirk.hashdata(seed)
		a = int.from_bytes(h[:coordlen], byteorder = "little") & ((1 << (curve.B - 1)) - 1)

		# Do we need to mask out lower significant bits to ensure that we use a
		# prime order subgroup?
		if curve.has_quirk(CurveQuirkEdDSAEnsurePrimeOrderSubgroup):
			if not Tools.is_power_of_two(curve.h):
				raise Exception("Can only ensure prime order subgroup by masking 'a' when curve cofactor is a power of two, h = %d isn't." % (curve.h))
			a &= ~(curve.h - 1)

		# Is the MSB of the curve always set to ensure constant runtime of the
		# Montgomery ladder?
		if curve.has_quirk(CurveQuirkEdDSASetPrivateKeyMSB):
			bit = curve.n.bit_length() + 1
			a |= (1 << bit)
		privkey = cls(a, curve)
		privkey.set_seed(seed)
		return privkey


class PrivKeyOpEDDSAEncode(object):
	def eddsa_encode(self):
		"""Performs serialization of a private key that is used for EdDSA."""
		return self.seed

	@classmethod
	def eddsa_decode(cls, curve, encoded_privkey):
		"""Performs decoding of a serialized private key as it is used for EdDSA."""
		return cls.eddsa_generate(curve, encoded_privkey)


class PrivKeyOpECDH(object):
	def ecdh_compute(self, peer_pubkey):
		"""Compute the shared secret point using our own private key and the
		public key of our peer."""
		return self.scalar * peer_pubkey.point


class PrivKeyOpLoad(object):
	@classmethod
	def load_derdata(cls, derdata):
		"""Loads an EC private key from a DER-encoded ASN.1 bytes object."""
		asn1 = parse_asn1_private_key(derdata)
		private_key_scalar = Tools.bytestoint(asn1["privateKey"])
		curve = CurveDB().get_curve_from_asn1(asn1["parameters"])
		return cls(private_key_scalar, curve)

	@classmethod
	def load_pem(cls, pemfilename):
		"""Loads an EC private key from a PEM-encoded 'EC PRIVATE KEY' file."""
		return cls.load_derdata(Tools.load_pem_data(pemfilename, "EC PRIVATE KEY"))

	@classmethod
	def load_der(cls, derfilename):
		"""Loads an EC private key from a DER-encoded ASN.1 file."""
		with open(derfilename, "rb") as f:
			data = f.read()
			return cls.load_derdata(data)
