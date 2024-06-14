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

from .AffineCurvePoint import AffineCurvePoint

class EllipticCurve(object):
	"""Elliptic curve base class. Provides functionality which all curves have
	in common."""
	def __init__(self, p, n, h, Gx, Gy, **kwargs):
		assert(isinstance(p, int))						# Modulus
		assert((n is None) or isinstance(n, int))		# Order
		assert((h is None) or isinstance(h, int))		# Cofactor
		assert((Gx is None) or isinstance(Gx, int))		# Generator Point X
		assert((Gy is None) or isinstance(Gy, int))		# Generator Point Y
		assert((Gx is None) == (Gy is None))			# Either both X and Y of G are set or none
		self._p = p
		self._n = n
		self._h = h
		if (Gx is not None) and (Gy is not None):
			self._G = AffineCurvePoint(Gx, Gy, self)
		else:
			self._G = None

		if "quirks" in kwargs:
			self._quirks = { quirk.identifier: quirk for quirk in kwargs["quirks"] }
		else:
			self._quirks = { }
	@property
	def p(self):
		"""Returns the prime modulus which constitutes the finite field in
		which the curve lies."""
		return self._p

	@property
	def n(self):
		"""Returns the order of the subgroup that is created by the generator
		G."""
		return self._n

	@property
	def h(self):
		"""Returns the cofactor of the generator subgroup, i.e. h = #E(F_p) /
		n. This will always be an integer according to Lagrange's Theorem."""
		return self._h

	@property
	def G(self):
		"""Returns the generator point G of the curve or None if no such point
		was set. The generator point generates a subgroup over #E(F_p)."""
		return self._G

	@property
	def curve_order(self):
		"""Returns the order of the curve in the underlying field, i.e.
		#E(F_p). Intuitively, this is the total number of points on the curve
		(plus maybe points at ininity, depending on the curve type) that
		satisfy the curve equation."""
		if (self.h is None) or (self.n is None):
			raise Exception("#E(F_p) is unknown for this curve")
		return self.h * self.n

	@property
	def frobenius_trace(self):
		"""Returns the Frobenius trace 't' of the curve. Since
		#E(F_p) = p + 1	- t it follows that t = p + 1 - #E(F_p)."""
		return self.p + 1 - self.curve_order

	@property
	def domainparams(self):
		"""Returns the curve parameters as a named tuple."""
		raise Exception(NotImplemented)

	@property
	def hasgenerator(self):
		"""Returns if a generator point was supplied for the curve."""
		return self.G is not None

	@property
	def hasname(self):
		"""Returns if the curve is named (i.e. its name is not None)."""
		return self.name is not None

	@property
	def name(self):
		"""Returns the name of the curve, if it was given one during
		construction. Purely informational."""
		return self._name

	@property
	def prettyname(self):
		"""Returns the pretty name of the curve type. This might depend on the
		actual curve, since it may also vary on the actual domain parameters to
		include if the curve is a Koblitz curve or not."""
		return self.pretty_name

	@property
	def curvetype(self):
		"""Returns a string that corresponds to the curve type. For example,
		this string can be 'shortweierstrass', 'twistededwards' or
		'montgomery'."""
		raise Exception(NotImplemented)

	@property
	def domainparamdict(self):
		"""Returns the domain parameters of the curve as a dictionary."""
		return dict(self.domainparams._asdict())

	@property
	def security_bit_estimate(self):
		"""Gives a haphazard estimate of the security of the underlying field,
		in bits. For most curves, this will be half the bitsize of n (but might
		be less, for example for Koblitz curves some bits might be
		subtracted)."""
		return self.n.bit_length() // 2

	def enumerate_points(self):
		"""Enumerates all points on the curve, including the point at infinity
		(if the curve has such a special point)."""
		raise Exception(NotImplemented)

	def naive_order_calculation(self):
		"""Naively calculates the order #E(F_p) of the curve by enumerating and
		counting all points which fulfull the curve equation. Note that this
		implementation only works for the smallest of curves and is
		computationally infeasible for all practical applications."""
		order = 0
		for pt in self.enumerate_points():
			order += 1
		return order

	def neutral(self):
		"""Returns the neutral element of the curve group (for some curves,
		this will be the point at infinity)."""
		return AffineCurvePoint(None, None, self)

	def is_neutral(self, P):
		"""Checks if a given point P is the neutral element of the group."""
		return P.x is None

	def oncurve(self, P):
		"""Checks is a given point P is on the curve."""
		raise Exception(NotImplemented)

	def point_addition(self, P, Q):
		"""Returns the sum of two points P and Q on the curve."""
		raise Exception(NotImplemented)

	def point_conjugate(self, P):
		"""Returns the negated point -P to a given point P."""
		raise Exception(NotImplemented)

	def compress(self, P):
		"""Returns the compressed representation of the point P on the
		curve. Not all curves may support this operation."""
		raise Exception(NotImplemented)

	def uncompress(self, compressed):
		"""Returns the uncompressed representation of a point on the curve. Not
		all curves may support this operation."""
		raise Exception(NotImplemented)

	def has_quirk(self, quirk_class):
		"""Some elliptic curves may have quirks or tweaks for certain
		algorithms. These are attached to the curve using the 'quirks' kwarg of
		the constructor.  Code that wants to query if a specific quirk is
		present may do so by calling 'has_quirk' with the according quirk class
		(not a quirk class instance!)."""
		return quirk_class.identifier in self._quirks

	def get_quirk(self, quirk_class):
		"""If a quirk is present for a given elliptic curve, this quirk may
		have been parametrized during instanciation. The get_quirk() method
		returns that quirk instance when given a specific quirk class as input.
		It raises a KeyError if the requested quirk is not present for the
		elliptic curve."""
		return self._quirks[quirk_class.identifier]

	def __eq__(self, other):
		return self.domainparams == other.domainparams

	def __ne__(self, other):
		return not (self == other)
