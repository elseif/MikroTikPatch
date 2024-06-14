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

import hashlib
import base64
import inspect

def bytestoint_le(data):
	"""Converts given bytes to a little-endian integer value."""
	return sum(value << (8 * index) for (index, value) in enumerate(data))

def inttobytes_le(value, length):
	"""Converts a little-endian integer value into a bytes object."""
	return bytes((value >> (8 * i)) & 0xff for i in range(length))

def bytestoint(data):
	"""Converts given bytes to a big-endian integer value."""
	return bytestoint_le(reversed(data))

def inttobytes(value, length):
	"""Converts a big-endian integer value into a bytes object."""
	return bytes((value >> (8 * i)) & 0xff for i in reversed(range(length)))

def bits_to_bytes(bitarray):
	"""Converts a tuple of bits (e.g. a ASN.1 BitString) to a bytes object.
	Only works when number of bits is a multiple of 8."""

	def bit_word_to_value(word):
		assert(len(word) == 8)
		return sum(value << i for (i, value) in enumerate(reversed(word)))

	assert((len(bitarray) % 8) == 0)
	return bytes(bit_word_to_value(bitarray[i : i + 8]) for i in range(0, len(bitarray), 8))

def ecdsa_msgdigest_to_int(message_digest, curveorder):
	"""Performs truncation of a message digest to the bitlength of the curve
	order."""
	# Convert message digest to integer value
	e = bytestoint(message_digest)

	# Truncate hash value if necessary
	msg_digest_bits = 8 * len(message_digest)
	if msg_digest_bits > curveorder.bit_length():
		shift = msg_digest_bits - curveorder.bit_length()
		e >>= shift

	return e

def load_pem_data(filename, specifier):
	"""Loads the PEM payload, designated with a BEGIN and END specifier, from a
	file given by its filename."""
	data = None
	with open(filename, "r") as f:
		spec_begin = "-----BEGIN " + specifier + "-----"
		spec_end = "-----END " + specifier + "-----"
		for line in f:
			line = line.rstrip()
			if (data is None) and (line == spec_begin):
				data = [ ]
			elif (data is not None) and (line == spec_end):
				break
			elif data is not None:
				data.append(line)
	if data is None:
		raise Exception("Trying to parse PEM file with specifier '%s', but no such block in file found." % (specifier))
	data = base64.b64decode("".join(data).encode("utf-8"))
	return data

def is_power_of_two(value):
	"""Returns True if the given value is a positive power of two, False
	otherwise."""
	while value > 0:
		if value == 1:
			return True
		elif (value & 1) == 1:
			return False
		value >>= 1
	return False
