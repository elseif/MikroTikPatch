#
#	toyecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2016 Johannes Bauer
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
from .CurveOps import CurveOpIsomorphism, CurveOpExportSage

_ShortWeierstrassCurveDomainParameters = collections.namedtuple("ShortWeierstrassCurveDomainParameters", [ "curvetype", "a", "b", "p", "n", "h", "G" ])

class ShortWeierstrassCurve(EllipticCurve, CurveOpIsomorphism, CurveOpExportSage):
	"""Represents an elliptic curve over a finite field F_P that satisfies the
	short Weierstrass equation y^2 = x^3 + ax + b."""
	pretty_name = "Short Weierstrass"

	def __init__(self, a, b, p, n, h, Gx, Gy, **kwargs):
		"""Create an elliptic curve given the equation coefficients a and b,
		the curve modulus p, the order of the curve n, the cofactor of the
		curve h and the generator point G's X and Y coordinates in affine
		representation, Gx and Gy."""
		EllipticCurve.__init__(self, p, n, h, Gx, Gy, **kwargs)
		assert(isinstance(a, int))		# Curve coefficent A
		assert(isinstance(b, int))		# Curve coefficent B
		self._a = FieldElement(a, p)
		self._b = FieldElement(b, p)
		self._name = kwargs.get("name")

		# Check that the curve is not singular
		assert((4 * (self.a ** 3)) + (27 * (self.b ** 2)) != 0)

		if self._G is not None:
			# Check that the generator G is on the curve
			assert(self._G.oncurve())

			if self.n is not None:
				# Check that the generator G is of curve order if a order was
				# passed as well
				assert((self.n * self.G).is_neutral)

	@classmethod
	def init_rawcurve(cls, a, b, p):
		"""Returns a raw curve which has an undiscovered amount of points
		#E(F_p) (i.e. the domain parameters n and h are not set). This function
		can be used to create a curve which is later completed by counting
		#E(F_p) using Schoof's algorithm."""
		return cls(a = a, b = b, p = p, n = None, h = None, Gx = None, Gy = None)

	@property
	def is_anomalous(self):
		"""Returns if the curve is anomalous, i.e. if #F(p) == p. If this is
		the case then there is an efficient method to solve the ECDLP.
		Therefore the curve is not suitable for cryptographic use."""
		return self.jinv in [ 0, 1728 ]

	@property
	@doc_inherit(EllipticCurve)
	def domainparams(self):
		return _ShortWeierstrassCurveDomainParameters(curvetype = self.curvetype, a = self.a, b = self.b, p = self.p, n = self.n, h = self.h, G = self.G)

	@property
	@doc_inherit(EllipticCurve)
	def curvetype(self):
		return "shortweierstrass"

	@property
	def is_koblitz(self):
		"""Returns whether the curve allows for efficient computation of a map
		\phi in the field (i.e. that the curve is commonly known as a 'Koblitz
		Curve'). This corresponds to examples 3 and 4 of the paper "Faster
		Point Multiplication on Elliptic Curves with Efficient Endomorphisms"
		by Gallant, Lambert and Vanstone."""
		return ((self.b == 0) and ((self.p % 4) == 1)) or ((self.a == 0) and ((self.p % 3) == 1))

	@property
	def security_bit_estimate(self):
		"""Returns the bit security estimate of the curve. Subtracts four bits
		security margin for Koblitz curves."""
		security_bits = self.n.bit_length() // 2
		if self.is_koblitz:
			security_bits -= 4
		return security_bits

	@property
	@doc_inherit(EllipticCurve)
	def prettyname(self):
		name = [ ]
		name.append(self.pretty_name)
		if self.is_koblitz:
			name.append("(Koblitz)")
		return " ".join(name)
	
	@property
	def a(self):
		"""Returns the coefficient a of the curve equation y^2 = x^3 + ax + b."""
		return self._a

	@property
	def b(self):
		"""Returns the coefficient b of the curve equation y^2 = x^3 + ax + b."""
		return self._b

	@property
	def jinv(self):
		"""Returns the j-invariant of the curve, i.e. 1728 * 4 * a^3 / (4 * a^3
		+ 27 * b^2)."""
		return 1728 * (4 * self.a ** 3) // ((4 * self.a ** 3) + (27 * self.b ** 2))

	def getpointwithx(self, x):
		"""Returns a tuple of two points which fulfill the curve equation or
		None if not such points exist."""
		assert(isinstance(x, int))
		yy = ((FieldElement(x, self._p) ** 3) + (self._a * x) + self._b)
		y = yy.sqrt()
		if y:
			return (AffineCurvePoint(x, int(y[0]), self), AffineCurvePoint(x, int(y[1]), self))
		else:
			return None

	@doc_inherit(EllipticCurve)
	def oncurve(self, P):
		return P.is_neutral or ((P.y ** 2) == (P.x ** 3) + (self.a * P.x) + self.b)

	@doc_inherit(EllipticCurve)
	def point_conjugate(self, P):
		return AffineCurvePoint(int(P.x), int(-P.y), self)

	@doc_inherit(EllipticCurve)
	def point_addition(self, P, Q):
		if P.is_neutral:
			# P is at infinity, O + Q = Q
			result = Q
		elif Q.is_neutral:
			# Q is at infinity, P + O = P
			result = P
		elif P == -Q:
			# P == -Q, return O (point at infinity)
			result = self.neutral()
		elif P == Q:
			# P == Q, point doubling
			s = ((3 * P.x ** 2) + self.a) // (2 * P.y)
			newx = s * s - (2 * P.x)
			newy = s * (P.x - newx) - P.y
			result = AffineCurvePoint(int(newx), int(newy), self)
		else:
			# P != Q, point addition
			s = (P.y - Q.y) // (P.x - Q.x)
			newx = (s ** 2) - P.x - Q.x
			newy = s * (P.x - newx) - P.y
			result = AffineCurvePoint(int(newx), int(newy), self)
		return result

	@doc_inherit(EllipticCurve)
	def compress(self, P):
		return (int(P.x), int(P.y) % 2)

	@doc_inherit(EllipticCurve)
	def uncompress(self, compressed):
		(x, ybit) = compressed
		x = FieldElement(x, self.p)
		alpha = (x ** 3) + (self.a * x) + self.b
		(beta1, beta2) = alpha.sqrt()
		if (int(beta1) % 2) == ybit:
			y = beta1
		else:
			y = beta2
		return AffineCurvePoint(int(x), int(y), self)

	@doc_inherit(EllipticCurve)
	def enumerate_points(self):
		yield self.neutral()
		for x in range(self.p):
			points = self.getpointwithx(x)
			if points is not None:
				yield points[0]
				yield points[1]

	def __str__(self):
		if self.hasname:
			return "ShortWeierstrassCurve<%s>" % (self.name)
		else:
			return "ShortWeierstrassCurve<y^2 = x^3 + 0x%x x + 0x%x mod 0x%x>" % (int(self.a), int(self.b), int(self.p))
