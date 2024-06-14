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

import collections
from .FieldElement import FieldElement
from .AffineCurvePoint import AffineCurvePoint
from .EllipticCurve import EllipticCurve
from .DocInherit import doc_inherit
import toyecc.MontgomeryCurve

_TwistedEdwardsCurveDomainParameters = collections.namedtuple("TwistedEdwardsCurveDomainParameters", [ "curvetype", "a", "d", "p", "n", "G" ])

class TwistedEdwardsCurve(EllipticCurve):
	"""Represents an elliptic curve over a finite field F_P that satisfies the
	Twisted Edwards equation a x^2 + y^2 = 1 + d x^2 y^2."""
	pretty_name = "Twisted Edwards"

	def __init__(self, a, d, p, n, h, Gx, Gy, **kwargs):
		"""Create an elliptic Twisted Edwards curve given the equation
		coefficients a and d, the curve field's modulus p, the order of the
		curve n and the generator point G's X and Y coordinates in affine
		representation, Gx and Gy."""
		EllipticCurve.__init__(self, p, n, h, Gx, Gy, **kwargs)
		assert(isinstance(a, int))		# Curve coefficent A
		assert(isinstance(d, int))		# Curve coefficent D
		self._a = FieldElement(a, p)
		self._d = FieldElement(d, p)
		self._name = kwargs.get("name")

		# Check that the curve is not singular
		assert(self.d * (1 - self.d) != 0)

		if self._G is not None:
			# Check that the generator G is on the curve
			assert(self._G.oncurve())

			# Check that the generator G is of curve order
			assert((self.n * self.G).is_neutral)

	@property
	@doc_inherit(EllipticCurve)
	def domainparams(self):
		return _TwistedEdwardsCurveDomainParameters(curvetype = self.curvetype, a = self.a, d = self.d, p = self.p, n = self.n, G = self.G)

	@property
	@doc_inherit(EllipticCurve)
	def curvetype(self):
		return "twistededwards"

	@property
	def a(self):
		"""Returns the coefficient a of the curve equation a x^2 + y^2 = 1 +
		d x^2 y^2."""
		return self._a

	@property
	def d(self):
		"""Returns the coefficient d of the curve equation a x^2 + y^2 = 1 +
		d x^2 y^2."""
		return self._d

	@property
	def B(self):
		"""Returns the length of the curve's field modulus in bits plus one."""
		return self._p.bit_length() + 1

	@property
	def is_complete(self):
		"""Returns if the twisted Edwards curve is complete. This is the case
		exactly when d is a quadratic non-residue modulo p."""
		return self.d.is_qnr

	@doc_inherit(EllipticCurve)
	def neutral(self):
		return AffineCurvePoint(0, 1, self)

	@doc_inherit(EllipticCurve)
	def is_neutral(self, P):
		return (P.x == 0) and (P.y == 1)

	@doc_inherit(EllipticCurve)
	def oncurve(self, P):
		return (self.a * P.x ** 2) + P.y ** 2 == 1 + self.d * P.x ** 2 * P.y ** 2

	@doc_inherit(EllipticCurve)
	def point_conjugate(self, P):
		return AffineCurvePoint(int(-P.x), int(P.y), self)

	@doc_inherit(EllipticCurve)
	def point_addition(self, P, Q):
		x = (P.x * Q.y + Q.x * P.y) // (1 + self.d * P.x * Q.x * P.y * Q.y)
		y = (P.y * Q.y - self.a * P.x * Q.x) // (1 - self.d * P.x * Q.x * P.y * Q.y)
		return AffineCurvePoint(int(x), int(y), self)

	def to_montgomery(self, b = None):
		"""Converts the twisted Edwards curve domain parameters to Montgomery
		domain parameters. For this conversion, b can be chosen semi-freely.
		If the native b coefficient is a quadratic residue modulo p, then the
		freely chosen b value must also be. If it is a quadratic non-residue,
		then so must be the surrogate b coefficient. If b is omitted, the
		native b value is used. The generator point of the twisted Edwards
		curve is also converted to Montgomery form. For this conversion,
		there's an invariant (one of two possible outcomes). An arbitrary
		bijection is used for this."""
		assert((b is None) or isinstance(b, int))

		# Calculate the native montgomery coefficents a, b first
		a = 2 * (self.a + self.d) // (self.a - self.d)
		native_b = 4 // (self.a - self.d)
		if b is None:
			b = native_b
		else:
			# If a b value was supplied, make sure is is either a QR or QNR mod
			# p, depending on what the native b value was
			b = FieldElement(b, self.p)
			if native_b.is_qr != b.is_qr:
				raise Exception("The b coefficient of the resulting curve must be a quadratic %s modulo p, %s is not." % ([ "non-residue", "residue" ][native_b.is_qr], str(b)))

		# Generate the raw curve without a generator yet
		raw_curve = toyecc.MontgomeryCurve.MontgomeryCurve(
			a = int(a),
			b = int(b),
			p = self.p,
			n = self.n,
			h = self.h,
			Gx = None,
			Gy = None,
		)

		# Then convert the original generator point using the raw curve to
		# yield a birationally equivalent generator point
		G_m = self.G.convert(raw_curve)

		# And create the curve again, setting this generator
		montgomery_curve = toyecc.MontgomeryCurve.MontgomeryCurve(
			a = int(a),
			b = int(b),
			p = self.p,
			n = self.n,
			h = self.h,
			Gx = int(G_m.x),
			Gy = int(G_m.y),
		)

		return montgomery_curve

	def __str__(self):
		if self.hasname:
			return "TwistedEdwardsCurve<%s>" % (self.name)
		else:
			return "TwistedEdwardsCurve<0x%x x^2 + y^2 = 1 + 0x%x x^2 y^2 mod 0x%x>" % (int(self.a), int(self.d), int(self.p))
