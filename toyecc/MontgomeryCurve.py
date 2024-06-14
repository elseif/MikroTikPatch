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
import toyecc.TwistedEdwardsCurve

_MontgomeryCurveDomainParameters = collections.namedtuple("MontgomeryCurveDomainParameters", [ "curvetype", "a", "b", "p", "n", "G" ])

class MontgomeryCurve(EllipticCurve):
	"""Represents an elliptic curve over a finite field F_P that satisfies the
	Montgomery equation by^2 = x^3 + ax^2 + x."""
	pretty_name = "Montgomery"

	def __init__(self, a, b, p, n, h, Gx, Gy, **kwargs):
		"""Create an elliptic Montgomery curve given the equation coefficients
		a and b, the curve modulus p, the order of the curve n, the cofactor of
		the curve h and the generator point G's X and Y coordinates in affine
		representation, Gx and Gy."""
		EllipticCurve.__init__(self, p, n, h, Gx, Gy, **kwargs)
		assert(isinstance(a, int))		# Curve coefficent A
		assert(isinstance(b, int))		# Curve coefficent B
		self._a = FieldElement(a, p)
		self._b = FieldElement(b, p)
		self._name = kwargs.get("name")

		# Check that the curve is not singular
		assert(self.b * ((self.a ** 2) - 4) != 0)

		if self._G is not None:
			# Check that the generator G is on the curve
			assert(self._G.oncurve())

			# Check that the generator G is of curve order
			assert((self.n * self.G).is_neutral)

	@property
	@doc_inherit(EllipticCurve)
	def domainparams(self):
		return _MontgomeryCurveDomainParameters(curvetype = self.curvetype, a = self.a, b = self.b, p = self.p, n = self.n, G = self.G)

	@property
	@doc_inherit(EllipticCurve)
	def curvetype(self):
		return "montgomery"

	@property
	def a(self):
		"""Returns the coefficient a of the curve equation by^2 = x^3 + ax^2 + x."""
		return self._a

	@property
	def b(self):
		"""Returns the coefficient b of the curve equation by^2 = x^3 + ax^2 + x."""
		return self._b

	@doc_inherit(EllipticCurve)
	def oncurve(self, P):
		return (P.is_neutral) or ((self.b * P.y ** 2) == (P.x ** 3) + (self.a * (P.x ** 2)) + P.x)

	@doc_inherit(EllipticCurve)
	def point_conjugate(self, P):
		return AffineCurvePoint(int(P.x), int(-P.y), self)

	@doc_inherit(EllipticCurve)
	def point_addition(self, P, Q):
		if P.is_neutral:
			# P is at infinity, O + Q = Q
			result = Q
		elif P == -Q:
			# P == -Q, return O (point at infinity)
			result = AffineCurvePoint.neutral(self)
		elif P == Q:
			# P == Q, point doubling
			newx = -2 * P.x - self.a + (3 * P.x**2 + 2 * P.x * self.a + 1)**2 // (4 * P.y**2 * self.b)
			newy = -P.y + (3 * P.x**2 + 2 * P.x * self.a + 1) * (3 * P.x + self.a) // (2 * P.y * self.b) - (3 * P.x**2 + 2 * P.x * self.a + 1)**3 // (8 * P.y**3 * self.b**2)
			result = AffineCurvePoint(int(newx), int(newy), self)
		else:
			# P != Q, point addition
			newx = -P.x - Q.x - self.a + (P.y - Q.y)**2 * self.b // (P.x - Q.x)**2
			newy = (2 * P.x + Q.x + self.a) * (P.y - Q.y) // (P.x - Q.x) - P.y - (P.y - Q.y)**3 * self.b // (P.x - Q.x)**3
			result = AffineCurvePoint(int(newx), int(newy), self)
		return result

	def to_twistededwards(self, a = None):
		"""Converts the domain parameters of this curve to domain parameters of
		a birationally equivalent twisted Edwards curve.  The user may select a
		desired a coefficient that the resulting Edwards curve shall have or
		leave it at None to accept an arbitrary one."""
		assert((a is None) or isinstance(a, int))

		# For the Montgomery curve, B can always be arbitrarily chosen as long
		# as the surrogate B coeffients are identical in their quadratic
		# residue property mod p. This means an Montgomery curve where B is a
		# quadratic residue mod p is isomorphous to all other Montgomery curves
		# with identical A, p and where B is also a quadratic residue mod p. We
		# use this property to get the curve we want if there is a desired "a"
		# outcome and choose B appropriately.
		if a is None:
			# No special wish for a, just do the normal conversion
			conversion_b = self.b
			a = (self.a + 2) // conversion_b
		else:
			# We desire a special a and calculate the B we want
			conversion_b = (self.a + 2) // a

			# And assure that it's QR property is the same as the original
			assert(conversion_b.is_qr == self.b.is_qr)
		d = (self.a - 2) // conversion_b

		# Then construct a curve with no generator first
		raw_curve = toyecc.TwistedEdwardsCurve.TwistedEdwardsCurve(
			a = int(a),
			d = int(d),
			p = self.p,
			n = self.n,
			h = self.h,
			Gx = None,
			Gy = None,
		)

		# Convert the generator point to the new curve
		G_twed = self.G.convert(raw_curve)

		# And recreate the curve with this new generator
		twed_curve = toyecc.TwistedEdwardsCurve.TwistedEdwardsCurve(
			a = int(a),
			d = int(d),
			p = self.p,
			n = self.n,
			h = self.h,
			Gx = int(G_twed.x),
			Gy = int(G_twed.y),
		)
		return twed_curve

	def __str__(self):
		if self.hasname:
			return "MontgomeryCurve<%s>" % (self.name)
		else:
			return "MontgomeryCurve<0x%x y^2 = x^3 + 0x%x x^2 + x mod 0x%x>" % (int(self.b), int(self.a), int(self.p))
