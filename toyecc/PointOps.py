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

from . import Tools
from .FieldElement import FieldElement
from .Exceptions import UnsupportedPointFormatException

class PointOpEDDSAEncoding(object):
	def eddsa_encode(self):
		"""Performs serialization of the point as required by EdDSA."""
		coordlen = (self.curve.B + 7) // 8
		bitlen = (coordlen * 8) - 1
		enc_value = int(self.y)
		enc_value &= ((1 << bitlen) - 1)
		enc_value |= (int(self.x) & 1) << bitlen
		return Tools.inttobytes_le(enc_value, (self.curve.B + 7) // 8)

	@staticmethod
	def __eddsa_recoverx(curve, y):
		x = 0
		xx = (y * y - 1) // (curve.d * y * y - curve.a)
		if curve.p % 8 == 5:
			x = xx ** ((curve.p + 3) // 8)
			if x * x == -xx:
				x = x * (FieldElement(2, curve.p) ** ((curve.p - 1) // 4))
		elif curve.p % 4 == 3:
			x = xx ** ((curve.p + 1) // 4)
			if x * x != xx:
				x = 0
		return int(x)

	@classmethod
	def eddsa_decode(cls, curve, data):
		"""Performs deserialization of the point as required by EdDSA."""
		assert(curve.curvetype == "twistededwards")
		coordlen = (curve.B + 7) // 8
		bitlen = (coordlen * 8) - 1
		enc_value = int.from_bytes(data, byteorder = "little")
		y = enc_value & ((1 << bitlen) - 1)
		x = PointOpEDDSAEncoding.__eddsa_recoverx(curve, y)
		hibit = (enc_value >> bitlen) & 1
		if (x & 1) != hibit:
			x = curve.p - x
		return cls(x, y, curve)

class PointOpCurveConversion(object):
	@staticmethod
	def __pconv_twed_mont_scalefactor(twedcurve, montcurve):
		native_b = 4 // (twedcurve.a - twedcurve.d)
		if native_b == montcurve.b:
			# Scaling is not necessary, already native curve format
			scale_factor = 1
		else:
			# Scaling of montgomery y component (v) is needed
			if twedcurve.hasgenerator and montcurve.hasgenerator:
				# Convert the generator point of the twisted edwards source
				# point to unscaled Montgomery space
				Gv = (1 + twedcurve.G.y) // ((1 - twedcurve.G.y) * twedcurve.G.x)

				# And calculate a multiplicative scaling factor so that the
				# point will result in the target curve's generator point Y
				scale_factor = montcurve.G.y // Gv

			elif native_b.is_qr:
				# If b is a quadradic residue mod p then any other
				# quadratic residue can serve as a surrgate b coefficient
				# to yield an isomorphous curve. Only y coordinate of the
				# resulting points needs to be scaled. Calculate a scaling
				# ratio.
				scale_factors = (montcurve.b // native_b).sqrt()

				# At least one of the curves lacks a generator point,
				# select just any scale factor
				scale_factor = scale_factors[0].inverse()

			else:
				# Native B is a quadratic non-residue module B; Not sure
				# how to handle this case
				# TODO: Implement this
				raise Exception(NotImplemented)
		return scale_factor

	def convert(self, targetcurve):
		"""Convert the affine curve point to a point on a birationally
		equivalent target curve."""

		if self.is_neutral:
			return targetcurve.neutral()

		if (self.curve.curvetype == "twistededwards") and (targetcurve.curvetype == "montgomery"):
			# (x, y) are Edwards coordinates
			# (u, v) are Montgomery coordonates
			(x, y) = (self.x, self.y)
			u = (1 + y) // (1 - y)
			v = (1 + y) // ((1 - y) * x)

			# Montgomery coordinates are unscaled to the actual B coefficient
			# of the curve right now. Calculate scaling factor and scale v
			# appropriately
			scaling_factor = self.__pconv_twed_mont_scalefactor(self.curve, targetcurve)
			v = v * scaling_factor

			point = self.__class__(int(u), int(v), targetcurve)
		elif (self.curve.curvetype == "montgomery") and (targetcurve.curvetype == "twistededwards"):
			# (x, y) are Edwards coordinates
			# (u, v) are Montgomery coordonates
			(u, v) = (self.x, self.y)
			y = (u - 1) // (u + 1)
			x = -(1 + y) // (v * (y - 1))

			# Twisted Edwards coordinates are unscaled to the actual B
			# coefficient of the curve right now. Calculate scaling factor and
			# scale x appropriately
			scaling_factor = self.__pconv_twed_mont_scalefactor(targetcurve, self.curve)
			x = x * scaling_factor

			point = self.__class__(int(x), int(y), targetcurve)
		else:
			raise Exception(NotImplemented)

		assert(point.oncurve())
		return point

class PointOpNaiveOrderCalculation(object):
	def naive_order_calculation(self):
		"""Calculates the order of the point naively, i.e. by walking through
		all points until the given neutral element is hit. Note that this only
		works for smallest of curves and is not computationally feasible for
		anything else."""
		curpt = self
		order = 1
		while not curpt.is_neutral:
			order += 1
			curpt += self
		return order


class PointOpSerialization(object):
	def serialize_uncompressed(self):
		"""Serializes the point into a bytes object in uncompressed form."""
		length = (self.curve.p.bit_length() + 7) // 8
		serialized = bytes([ 0x04 ]) + Tools.inttobytes(int(self.x), length) + Tools.inttobytes(int(self.y), length)
		return serialized

	@classmethod
	def deserialize_uncompressed(cls, data, curve = None):
		"""Deserializes a curve point which is given in uncompressed form. A
		curve may be passed with the 'curve' argument in which case an
		AffineCurvePoint is returned from this method. Otherwise the affine X
		and Y coordinates are returned as a tuple."""
		if data[0] != 0x04:
			raise UnsupportedPointFormatException("Generator point of explicitly encoded curve is given in unsupported form (0x%x)." % (data[0]))
		data = data[1:]
		assert((len(data) % 2) == 0)
		Px = Tools.bytestoint(data[ : len(data) // 2])
		Py = Tools.bytestoint(data[len(data) // 2 : ])
		if curve is not None:
			return cls(Px, Py, curve)
		else:
			return (Px, Py)

class PointOpScalarMultiplicationXOnly():
	"""Compute an X-only ladder scalar multiplication of the private key and
	the X coordinate of a given point."""
	def _x_double(self, x):
		"""Doubling of point with coordinate x."""
		if x is None:
			return None

		den = 4 * (x**3 + self.curve.a * x + self.curve.b)
		if den == 0:
			# Point at infinity
			return None
		num = (x**2 - self.curve.a)**2 - (8 * self.curve.b * x)
		return num // den

	def _x_add_multiplicative(self, x1, x2, x3prime):
		"""Multiplicative formula addition of x1 + x2, where x3' is the
		difference in X of P1 - P2. Using this function only makes sense where
		(P1 - P2) is fixed, as it is in the ladder implementation."""
		if x1 is None:
			return x2
		elif x2 is None:
			return x1
		elif x1 == x2:
			return None
		num = -4 * self.curve.b * (x1 + x2) + (x1 * x2 - self.curve.a)**2
		den = x3prime * (x1 - x2)**2
		result = num // den
		return result

	def _x_add_additive(self, x1, x2, x3prime):
		"""Additive formula addition of x1 + x2, where x3' is the difference in
		X of P1 - P2. Using this function only makes sense where (P1 - P2) is
		fixed, as it is in the ladder implementation."""
		if x1 is None:
			return x2
		elif x2 is None:
			return x1
		elif x1 == x2:
			return None
		num = 2 * (x1 + x2) * (x1 * x2 + self.curve.a) + 4 * self.curve.b
		den = (x1 - x2) ** 2
		result = num // den - x3prime
		return result

	def _x_add(self, x1, x2, x3prime):
		"""There are two equivalent implementations, one using the
		multiplicative and the other using the additive representation. Both
		should work equally well."""
		return self._x_add_multiplicative(x1, x2, x3prime)
		#return self._x_add_additive(x1, x2, x3prime)

	def scalar_mul_xonly(self, scalar):
		"""This implements the X-coordinate-only multiplication algorithm of a
		Short Weierstrass curve with the X coordinate of a given point.
		Reference is "Izu and Takagi: A Fast Parallel Elliptic Curve
		Multiplication Resistant against Side Channel Attacks" (2002)"""
		if self.curve.curvetype != "shortweierstrass":
			raise NotImplementedError("X-only ladder multiplication is only implemented for Short Weierstrass curves")
		if self.is_neutral:
			# Point at infinity is input
			return None
		elif scalar == 0:
			# Multiplication with zero -> point at infinity is output
			return None

		x_coordinate = int(self.x)
		if not isinstance(x_coordinate, FieldElement):
			x_coordinate = FieldElement(x_coordinate, self.curve.p)
		Q = [ x_coordinate, self._x_double(x_coordinate), None ]
		for bitno in reversed(range(scalar.bit_length() - 1)):
			bit = (scalar >> bitno) & 1
			Q[2] = self._x_double(Q[bit])
			Q[1] = self._x_add(Q[0], Q[1], x_coordinate)
			Q[0] = Q[2 - bit]
			Q[1] = Q[1 + bit]
		return Q[0]
