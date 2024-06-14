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

from .FieldElement import FieldElement
from .Exceptions import NoSuchCurveException

class CurveOpIsomorphism(object):
	def _twist(self, d = None, sqrt_d = None):
		"""Returns the twisted curve with the twist coefficient d. If d is a
		quadratic non-residue mod p then this function will yield a curve that
		is isomorphous on the field extension GF(sqrt(d)). If it is a quadratic
		residue, it will return an GF(p)-isomorphous curve."""
		assert(self.curvetype == "shortweierstrass")
		ShortWeierstrassCurve = self.__class__

		if sqrt_d is not None:
			# If a square root is given, then it must be a correct square root
			assert(sqrt_d ** 2 == d)

		a = self.a * (d ** 2)
		b = self.b * (d ** 3)
		if d.is_qr and self.hasgenerator:
			# Quadratic twist will return an GF(p)-isomorphous curve -> convert
			# generator point as well
			if sqrt_d is None:
				sqrt_d = d.sqrt()[0]
			Gx = int(self.G.x * d)
			Gy = int(self.G.y * (sqrt_d ** 3))

			n = self.n
			h = self.h
		else:
			# Quadratic twist will return an isomorphous curve on the
			# GF(sqrt(d)) field extension -> no generator point conversion for
			# now
#			Gx = int(self.G.x * d)
#			Gy = int(self.G.y * d)
			Gx = None
			Gy = None

			# If the original curve had q + 1 - t points, then its twist will
			# have q + 1 + t points. TODO: Does this help us to find the order
			# of the generator point G? I don't think it does :-( Leave n and h
			# therefore unset for the moment.
			n = None
			h = None

		return ShortWeierstrassCurve(a = int(a), b = int(b), p = self.p, n = n, h = h, Gx = Gx, Gy = Gy)

	def twist(self, d = None):
		"""If the twist coefficient d is omitted, the function will
		automatically look for an arbitrary quadratic non-residue in F_P."""
		if d == 0:
			raise Exception("Domain error: d must be nonzero.")
		elif d is None:
			# Search for a QNR in F_P
			d = FieldElement.any_qnr(self.p)
		else:
			d = FieldElement(d, self.p)
			if d.is_qr:
				raise Exception("Twist requested, but twist coefficient d is a quadratic-residue mod p. Refusing to return a GF(p)-isomorphic curve; if you want this behavior, use twist_fp_isomorphic()")
		return self._twist(d)

	def twist_fp_isomorphic(self, u):
		"""Returns a GF(p)-isomorphous curve by applying the substituting
		transformation x = u^2 x' and y = u^3 y' on the curve equation. The
		function therefore returns a quadratic twist with d = u^2, i.e. it
		ensures that the twist coefficient d is a quadratic residue mod p.."""
		if u == 0:
			raise Exception("Domain error: u must be nonzero.")
		return self._twist(FieldElement(u ** 2, self.p), FieldElement(u, self.p))

	def twist_fp_isomorphic_fixed_a(self, a):
		"""Tries to find an GF(p)-isomorphous curve which has a particular
		given value for the curve coefficient 'a'."""

		# anew = a * u^4 -> u = quartic_root(anew / a)
		scalar = a // self.a
		u = scalar.quartic_root()
		if u is None:
			raise NoSuchCurveException("Cannot find an isomorphism so that a = %d because %s has no quartic root in F_P" % (a, scalar))
		return self.twist_fp_isomorphic(int(u))

	def is_isomorphous_curve(self, other):
		"""Returns if the given curve 'other' is isomorphous in the same field
		as the given curve curve."""
		if other.p != self.p:
			return False

		try:
			iso = self.twist_fp_isomorphic_fixed_a(other.a)
		except NoSuchCurveException:
			# No isomorphous curve with this value for a exists
			return False

		# The curves should be identical after the transformation if they're
		# isomorphous to each other
		return (iso.a == other.a) and (iso.b == other.b)

class CurveOpExportSage(object):
	def export_sage(self, varname = "curve"):
		"""Exports the elliptic curve to statements that can be used within the
		SAGE computer algebra system."""

		# EllipticCurve([a1,a2,a3,a4,a6]) means in Sage:
		# y² + a1 x y + a3 y = x³ + a2 x² + a4 x + a6
		# i.e. for Short Weierstrass a4 = A, a6 = B

		statements = [ ]
		statements.append("# %s" % (str(self)))
		statements.append("%s_p = 0x%x" % (varname, int(self.p)))
		statements.append("%s_F = GF(%s_p)" % (varname, varname))
		if self.curvetype == "shortweierstrass":
			statements.append("%s_a = 0x%x" % (varname, int(self.a)))
			statements.append("%s_b = 0x%x" % (varname, int(self.b)))
			statements.append("%s = EllipticCurve(%s_F, [ %s_a, %s_b ])" % (varname, varname, varname, varname))
		else:
			raise Exception(NotImplemented)

		return statements
