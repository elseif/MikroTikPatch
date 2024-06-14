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

from .PubKeyOps import PubKeyOpECDSAVerify, PubKeyOpECDSAExploitReusedNonce, PubKeyOpEDDSAVerify, PubKeyOpEDDSAEncode, PubKeyOpECIESEncrypt, PubKeyOpLoad

class ECPublicKey(PubKeyOpECDSAVerify, PubKeyOpECDSAExploitReusedNonce, PubKeyOpEDDSAVerify, PubKeyOpEDDSAEncode, PubKeyOpECIESEncrypt, PubKeyOpLoad):
	"""Elliptic curve public key abstraction. An EC public key is just a point
	on the curve, which is why the constructor only takes this (public) point
	as a parameter. The public key abstraction allows this point to be used in
	various meaningful purposes (ECDSA signature verification, etc.)."""

	def __init__(self, point):
		self._point = point

	@property
	def curve(self):
		return self._point.curve

	@property
	def point(self):
		return self._point

	def __str__(self):
		return "PublicKey<%s>" % (str(self.point))
