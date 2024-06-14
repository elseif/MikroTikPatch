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

from .Polynomial import Polynomial

class DivisionPolynomial(object):
	def __init__(self, curve):
		"""Creates a division polynomial generator which returns \psi_i for the
		given curve in Weierstrass form."""
		self._curve = curve
		assert(self._curve.curvetype == "shortweierstrass")
		self._cache = { }
		self._curvepoly = None
		self._initcache()

	def _initcache(self):
		(a, b) = (self.curve.a, self.curve.b)
		x = Polynomial(self.curve.p)
		self._cache[0] = Polynomial(self.curve.p, 0)
		self._cache[1] = Polynomial(self.curve.p, 1)
		self._cache[2] = Polynomial(self.curve.p, 2)
		self._cache[3] = (3 * x**4) + (6 * a * x**2) + (12 * b * x) - (a**2)
		self._cache[4] = 4 * (x**6 + (5 * a * x**4) + (20 * b * x**3) - (5 * a**2 * x**2) - (4 * a * b * x) - (8 * b**2) - (a**3))
		self._curvepoly = x**3 + (a * x) + b

	@property
	def curve(self):
		return self._curve

	def __getitem__(self, index):
		if index not in self._cache:
			m = index // 2
			if (index % 2) == 1:
				# The paper says this would be correct:
				# result = (self[m + 2] * self[m]**3) - (self[m - 1] * self[m + 1] ** 3)
				# But MIRACL does it differently. Use the MIRACL approach:
				if (m % 2) == 0:
					result = (self._curvepoly**2 * self[m + 2] * self[m]**3) - (self[m - 1] * self[m + 1]**3)
				else:
					result = (self[m + 2] * self[m]**3) - (self._curvepoly**2 * self[m - 1] * self[m + 1]**3)
			else:
				result = (self[m] // 2) * ((self[m + 2] * self[m - 1]**2) - (self[m - 2] * self[m + 1]**2))
			self._cache[index] = result
		return self._cache[index]

	def __str__(self):
		return "DivisionPolys<%s, %d cached>" % (str(self.curve), len(self._cache))
