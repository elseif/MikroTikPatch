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

import math

from .FieldElement import FieldElement
from .PointOps import PointOpEDDSAEncoding, PointOpCurveConversion, PointOpNaiveOrderCalculation, PointOpSerialization, PointOpScalarMultiplicationXOnly

class AffineCurvePoint(PointOpEDDSAEncoding, PointOpCurveConversion, PointOpNaiveOrderCalculation, PointOpSerialization, PointOpScalarMultiplicationXOnly):
	"""Represents a point on a curve in affine (x, y) representation."""

	def __init__(self, x, y, curve):
		"""Generate a curve point (x, y) on the curve 'curve'. x and y have to
		be integers. If the neutral element of the group O (for some curves,
		this is a point at infinity) should be created, use the static method
		'neutral', since representations of O differ on various curves (e.g. in
		short Weierstrass curves, they have no explicit notation in affine
		space while on twisted Edwards curves they do."""
		# Either x and y are None (Point at Infty) or both are defined
		assert(((x is None) and (y is None)) or ((x is not None) and (y is not None)))
		assert((x is None) or isinstance(x, int))
		assert((y is None) or isinstance(y, int))
		if x is None:
			# Point at infinity
			self._x = None
			self._y = None
		else:
			self._x = FieldElement(x, curve.p)
			self._y = FieldElement(y, curve.p)
		self._curve = curve

	@staticmethod
	def neutral(curve):
		"""Returns the neutral element of the curve group."""
		return curve.neutral()

	@property
	def is_neutral(self):
		"""Indicates if the point is the neutral element O of the curve (point
		at infinity for some curves)."""
		return self.curve.is_neutral(self)

	@property
	def x(self):
		"""Affine X component of the point, field element of p."""
		return self._x

	@property
	def y(self):
		"""Affine Y component of the point, field element of p."""
		return self._y

	@property
	def curve(self):
		"""Curve that the point is located on."""
		return self._curve

	def __add__(self, other):
		"""Returns the point addition."""
		assert(isinstance(other, AffineCurvePoint))
		return self.curve.point_addition(self, other)

	def __rmul__(self, other):
		return self * other

	def __neg__(self):
		"""Returns the conjugated point."""
		return self.curve.point_conjugate(self)

	def __mul__(self, scalar):
		"""Returns the scalar point multiplication. The scalar needs to be an
		integer value."""
		assert(isinstance(scalar, int))
		assert(scalar >= 0)

		result = self.curve.neutral()
		n = self
		if scalar > 0:
			for bit in range(scalar.bit_length()):
				if (scalar & (1 << bit)):
					result = result + n
				n = n + n
		#assert(result.oncurve())
		return result

	def __eq__(self, other):
		return (self.x, self.y) == (other.x, other.y)

	def __ne__(self, other):
		return not (self == other)

	def __hash__(self):
		return hash((self.x, self.y))

	def oncurve(self):
		"""Indicates if the given point is satisfying the curve equation (i.e.
		if it is a point on the curve)."""
		return self.curve.oncurve(self)

	def compress(self):
		"""Returns the compressed point format (if this is possible on the
		given curve)."""
		return self.curve.compress(self)

	def __repr__(self):
		return str(self)

	def __str__(self):
		if self.is_neutral:
			return "(neutral)"
		else:
			return "(0x%x, 0x%x)" % (int(self.x), int(self.y))
