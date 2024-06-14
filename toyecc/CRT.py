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

class CRT():
	"""Implements the Chinese Remainder Theorem algorithm where a number of
	modular congruences are given that all need to be satisfied."""
	def __init__(self):
		self._moduli = { }

	def add(self, value, modulus):
		"""Adds a value that shall be returned when the result is taken modulo
		the given modulus."""
		assert(modulus not in self._moduli)
		assert(isinstance(value, int))
		assert(isinstance(modulus, int))
		self._moduli[modulus] = value
		return self

	def solve(self):
		"""Solve the Chinese Remainder Theorem for the given values and
		moduli."""
		# Calculate product of all moduli
		product = 1
		for modulus in self._moduli.keys():
			product *= modulus

		# Then determine the solution
		solution = 0
		for modulus in self._moduli.keys():
			if self._moduli[modulus] == 0:
				continue

			rem_product = product // modulus
			one_value = int(FieldElement(rem_product, modulus).inverse())
			solution += rem_product * one_value * self._moduli[modulus]

		return solution % product
