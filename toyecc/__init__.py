"""toyecc - Elliptic Curve Cryptography demonstration library

toyecc is a library that is supposed to demonstrate and teach how Elliptic
Curve Cryptography (ECC) works. It is implemented in pure Python and neither
aims to be feature-complete not side-channel resistant nor secure in any way.
Please keep this in mind when using toyecc. Certain algorithms have been
deliberately implemented exactly without precautions against side-channel
attacks in order to cleanly demonstrate the concepts.

There is a curve database included in toyecc which already knows lots of
interesting elliptic curves by name:

	import toyecc
	curve = toyecc.getcurvebyname("secp112r1")
	print(curve)
		ShortWeierstrassCurve<secp112r1>

On this curve you can now create a public/private keypair:

	privkey = toyecc.ECPrivateKey.generate(curve)
	print(privkey)
		PrivateKey<d = 0x89fb9821aa5154c9934b3e0268ef>
	print(privkey.pubkey)
		PublicKey<(0x69976db41f5e487928463b9f8a38, 0xda1fdba3de89c58683bd2d635430)>

You can also regenerate this keypair later on if you wish to remain it static
and not change with every invocation:

	privkey = toyecc.ECPrivateKey(0x89fb9821aa5154c9934b3e0268ef, curve)
	print(privkey)
		PrivateKey<d = 0x89fb9821aa5154c9934b3e0268ef>

You can use this keypair to perform actions like ECDSA signing:

	signature = privkey.ecdsa_sign(b"Foobar", "sha1")
	print(signature)
	ECDSASignature(hashalg='sha1', r=1762251013383878369191057972852867, s=3691758261134002001156831324480002)

If you want to recreate a public key anew, you can also do so by first creating
the public point:

	pubkeypt = toyecc.AffineCurvePoint(0x69976db41f5e487928463b9f8a38, 0xda1fdba3de89c58683bd2d635430, curve)
	print(pubkeypt)
		(0x69976db41f5e487928463b9f8a38, 0xda1fdba3de89c58683bd2d635430)

Then you can just wrap the point in a ECPublicKey object to have access to
methods like ECDSA verification and such:

	pubkey = toyecc.ECPublicKey(pubkeypt)
	print(pubkey)
		PublicKey<(0x69976db41f5e487928463b9f8a38, 0xda1fdba3de89c58683bd2d635430)>

Lastly, you can verify the signature you created earlier:

	pubkey.ecdsa_verify(b"Foobar", signature)
		True

And change the message so the signature would become invalid:

	pubkey.ecdsa_verify(b"Barfoo", signature)
		False
"""

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
from .AffineCurvePoint import AffineCurvePoint
from .CurveDB import getcurvedb, getcurveentry, getcurvebyname, getcurvenames
from .ECPrivateKey import ECPrivateKey
from .ECPublicKey import ECPublicKey
from .ShortWeierstrassCurve import ShortWeierstrassCurve
from .CRT import CRT

VERSION = "0.0.9rc0"
