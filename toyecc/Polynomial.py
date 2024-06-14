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

import re
import collections

from .FieldElement import FieldElement

class _CoeffDict(object):
	def __init__(self):
		self._coeffs = { }

	def clone(self):
		clone = _CoeffDict()
		clone._coeffs = dict(self._coeffs)
		return clone

	@property
	def degree(self):
		if len(self._coeffs) > 0:
			return max(self._coeffs.keys())
		else:
			return 0

	def clone(self):
		clone = _CoeffDict()
		clone._coeffs = dict(self._coeffs)
		return clone

	def __eq__(self, other):
		return self._coeffs == other._coeffs

	def __neq__(self, other):
		return not (self == other)

	def __iter__(self):
		return iter(self._coeffs.items())

	def __len__(self):
		return len(self._coeffs)

	def __getitem__(self, key):
		return self._coeffs.get(key, 0)

	def __setitem__(self, key, value):
		if (value == 0) and (key in self._coeffs):
			del self._coeffs[key]
		else:
			self._coeffs[key] = value

	def __str__(self):
		return "CoeffDict<%s>" % (str(self._coeffs))

class Polynomial(object):
	_TERM_RE = re.compile("^((?P<coeff>-?\d+)\*)?x(\^(?P<exponent>\d+))?$")
	_CACHE_EXPONENTS = [ 2, 3 ]

	def __init__(self, modulus, initvalue = None):
		self._modulus = modulus
		self._terms = _CoeffDict()
		if initvalue is None:
			self._terms[1] = FieldElement(1, self._modulus)
		else:
			if initvalue != 0:
				self._terms[0] = FieldElement(initvalue, self._modulus)
		self._expcache = { }

	@property
	def degree(self):
		return self._terms.degree

	@property
	def modulus(self):
		return self._modulus

	@property
	def is_constant(self):
		return self.degree == 0

	def get_constant(self):
		assert(self.is_constant)
		return self[0]

	def _clone(self):
		clone = Polynomial(self.modulus, 0)
		clone._terms = self._terms.clone()
		return clone

	def substitute(self, value):
		result = 0
		for (exponent, coefficient) in self._terms:
			result += coefficient * (value ** exponent)
		return result

	def gcd(self, other):
		"""Returns the greatest common divisor polynomial of this object and
		the other polynomial."""
		assert(isinstance(other, Polynomial))
		assert(self.modulus == other.modulus)
		assert((self != 0) or (other != 0))
		(a, b) = (self, other)
		if a == 0:
			return b
		elif b == 0:
			return a

		while b != 0:
			(a, b) = (b, a % b)

		highest_coefficient = a._terms[a.degree]
		a = a // highest_coefficient
		return a

	def __and__(self, other):
		"""Returns the greatest common divisor polynomial of this object and
		the other polynomial."""
		return self.gcd(other)

	def __add__(self, value):
		if isinstance(value, int) or isinstance(value, FieldElement):
			result = self._clone()
			result._terms[0] += value
			return result
		elif isinstance(value, Polynomial):
			result = self._clone()
			for (exponent, coefficient) in value:
				result._terms[exponent] += coefficient
			return result
		else:
			raise Exception(NotImplemented)

	def __sub__(self, value):
		if isinstance(value, int) or isinstance(value, FieldElement):
			result = self._clone()
			result._terms[0] -= value
			return result
		elif isinstance(value, Polynomial):
			result = self._clone()
			for (exponent, coefficient) in value:
				result._terms[exponent] -= coefficient
			return result
		else:
			raise Exception(NotImplemented)

	def __pow__(self, value):
		if value in self._expcache:
			return self._expcache[value]
		if isinstance(value, int):
			if len(self._terms) == 1:
				result = Polynomial(self.modulus, 0)
				for (exponent, coefficient) in self:
					result._terms[exponent * value] = coefficient ** value
			else:
				exponent = value
				result = Polynomial(self.modulus, 1)
				multiplier = self
				for bit in range(exponent.bit_length()):
					if exponent & (1 << bit):
						result = result * multiplier
					multiplier = multiplier * multiplier
		else:
			raise Exception(NotImplemented)

		if value in self._CACHE_EXPONENTS:
			self._expcache[value] = result

		return result

	def powmod(self, exponent, modulus):
		"""Returns the result of (self^exponent) % modulus. Exponent must be an
		integer and modulus another Polynomial."""
		assert(isinstance(exponent, int))
		assert((modulus is None) or isinstance(modulus, Polynomial))
		assert(exponent >= 0)
		result = Polynomial(self.modulus, 1)
		multiplier = self
		for bit in range(exponent.bit_length()):
			if exponent & (1 << bit):
				result = (result * multiplier) % modulus
			multiplier = (multiplier * multiplier) % modulus
		return result

	@classmethod
	def parse_poly(cls, polystr, modulus):
		poly = Polynomial(modulus, 0)

		polystr = polystr.replace(" - ", " + -")
		terms = polystr.split(" + ")
		for term in terms:
			if term.isnumeric():
				poly._terms[0] += int(term)
			else:
				result = cls._TERM_RE.match(term)
				if result is None:
					raise Exception("Cannot parse polynomial term: '%s'" % (term))
				result = result.groupdict()

				result = { key: int(value) for (key, value) in result.items() if (value is not None) }
				coeff = result.get("coeff", 1)
				exponent = result.get("exponent", 1)
				poly._terms[exponent] += FieldElement(coeff, modulus)

		return poly

	def __floordiv__(self, value):
		if isinstance(value, int) or isinstance(value, FieldElement):
			result = Polynomial(self.modulus, 0)
			for (exponent, coefficient) in self:
				result._terms[exponent] = coefficient // value
			return result
		elif isinstance(value, Polynomial):
			if value.degree == 0:
				return self // value[0]

			result = Polynomial(self.modulus, 0)
			numerator = self._clone()
			while numerator.degree >= value.degree:
				shift = numerator.degree - value.degree
				multiplier = numerator[numerator.degree] // value[value.degree]

				result._terms[shift] += multiplier
				for (exponent, coefficient) in value:
					numerator._terms[exponent + shift] -= multiplier * coefficient
			return result

		else:
			raise Exception(NotImplemented)

	def __mul__(self, value):
		if isinstance(value, int) or isinstance(value, FieldElement):
			result = Polynomial(self.modulus, 0)
			for (exponent, coefficient) in self:
				result._terms[exponent] = coefficient * value
			return result
		elif isinstance(value, Polynomial):
			result = Polynomial(self.modulus, 0)
			for (exponent1, coefficient1) in self:
				for (exponent2, coefficient2) in value:
					result._terms[exponent1 + exponent2] += coefficient1 * coefficient2
			return result
		else:
			raise Exception(NotImplemented)

	def __mod__(self, value):
		if isinstance(value, Polynomial):
			if value.degree == 0:
				return Polynomial(self.modulus, 0)

			result = self._clone()
			while result.degree >= value.degree:
				shift = result.degree - value.degree
				multiplier = result[result.degree] // value[value.degree]

				for (exponent, coefficient) in value:
					result._terms[exponent + shift] -= multiplier * coefficient
			return result
		else:
			raise Exception(NotImplemented)

	def __rmul__(self, value):
		return self * value

	def __radd__(self, value):
		return self + value

	def __getitem__(self, exponent):
		return self._terms[exponent]

	def __iter__(self):
		yield from iter(self._terms)

	def __eq__(self, value):
		if isinstance(value, int) or isinstance(value, FieldElement):
			return self.is_constant and (self.get_constant() == value)
		elif isinstance(value, Polynomial):
			return (self.modulus == value.modulus) and (self._terms == value._terms)
		else:
			raise Exception(NotImplemented)

	def __ne__(self, value):
		return not (self == value)

	def __repr__(self):
		return str(self)

	def __str__(self):
		terms = [ ]
		for (exponent, coefficient) in sorted(self, reverse = True):
			if coefficient == 0:
				continue

			if exponent == 0:
				terms.append("%d" % (int(coefficient)))
				continue

			elif coefficient == 1:
				coeffstr = ""
			else:
				coeffstr = "%d*" % (int(coefficient))

			if exponent == 1:
				termstr = "x"
			else:
				termstr = "x^%d" % (int(exponent))

			terms.append(coeffstr + termstr)

		if len(terms) == 0:
			return "0"
		else:
			return " + ".join(terms)
