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

try:
	from pyasn1.type import univ, namedtype, tag
	import pyasn1.codec.ber.decoder

	class ECPVer(univ.Integer):
		"""RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

		ECPVer ::= INTEGER {ecpVer1(1)}
		"""
		pass

	class FieldElement(univ.OctetString):
		"""RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

		FieldElement ::= OCTET STRING
		"""
		pass

	class ECPoint(univ.OctetString):
		"""RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

		ECPoint ::= OCTET STRING
		"""
		pass

	class Curve(univ.Sequence):
		"""RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

		Curve ::= SEQUENCE {
			a         FieldElement,
			b         FieldElement,
			seed      BIT STRING OPTIONAL
		}
		"""
		componentType = namedtype.NamedTypes(
			namedtype.NamedType("a", FieldElement()),
			namedtype.NamedType("b", FieldElement()),
			namedtype.OptionalNamedType("seed", univ.BitString()),
		)

	class FieldID(univ.Sequence):
		"""RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

		FieldID ::= SEQUENCE {
			fieldType   OBJECT IDENTIFIER,
			parameters  ANY DEFINED BY fieldType
		}
		"""
		componentType = namedtype.NamedTypes(
			namedtype.NamedType("fieldType", univ.ObjectIdentifier()),
			namedtype.NamedType("parameters", univ.Any()),
		)

	class SpecifiedECDomain(univ.Sequence):
		"""RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile

		ECParameters ::= SEQUENCE {
			version   ECPVer,          -- version is always 1
			fieldID   FieldID,         -- identifies the finite field over which the curve is defined
			curve     Curve,           -- coefficients a and b of the elliptic curve
			base      ECPoint,         -- specifies the base point P on the elliptic curve
			order     INTEGER,         -- the order n of the base point
			cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n
		}
		"""
		componentType = namedtype.NamedTypes(
			namedtype.NamedType("version", ECPVer()),
			namedtype.NamedType("fieldID", FieldID()),
			namedtype.NamedType("curve", Curve()),
			namedtype.NamedType("base", ECPoint()),
			namedtype.NamedType("order", univ.Integer()),
			namedtype.OptionalNamedType("cofactor", univ.Integer()),
		)

	class ECParameters(univ.Choice):
		"""RFC 5480: Elliptic Curve Cryptography Subject Public Key Information

		ECParameters ::= CHOICE {
			namedCurve      OBJECT IDENTIFIER
			implicitCurve   NULL
			specifiedCurve  SpecifiedECDomain
		 }
		"""
		componentType = namedtype.NamedTypes(
			namedtype.NamedType("namedCurve", univ.ObjectIdentifier()),
			namedtype.NamedType("implicitCurve", univ.Null()),
			namedtype.NamedType("specifiedCurve", SpecifiedECDomain()),
		)


	class ECPrivateKey(univ.Sequence):
		"""RFC 5915: Elliptic Curve Private Key Structure

		ECPrivateKey ::= SEQUENCE {
			version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
			privateKey     OCTET STRING,
			parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
			publicKey  [1] BIT STRING OPTIONAL
		}
		"""
		componentType = namedtype.NamedTypes(
			namedtype.NamedType("version", univ.Integer()),
			namedtype.NamedType("privateKey", univ.OctetString()),
			namedtype.OptionalNamedType("parameters", ECParameters().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
			namedtype.OptionalNamedType("publicKey", univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
		)

	class AlgorithmIdentifier(univ.Sequence):
		"""RFC 5480: Elliptic Curve Cryptography Subject Public Key Information

		AlgorithmIdentifier  ::=  SEQUENCE  {
			algorithm   OBJECT IDENTIFIER,
			parameters  ANY DEFINED BY algorithm OPTIONAL
		}
		"""
		componentType = namedtype.NamedTypes(
			namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
			namedtype.NamedType("parameters", ECParameters()),
		)

	class ECPublicKey(univ.Sequence):
		"""RFC 5480: Elliptic Curve Cryptography Subject Public Key Information

		SubjectPublicKeyInfo  ::=  SEQUENCE  {
			algorithm         AlgorithmIdentifier,
			subjectPublicKey  BIT STRING
		}
		"""
		componentType = namedtype.NamedTypes(
			namedtype.NamedType("algorithm", AlgorithmIdentifier()),
			namedtype.NamedType("subjectPublicKey", univ.BitString()),
		)

	class FieldFPParameters(univ.Integer):
		"""For F_P fields, the field parameters is just the integer P."""
		pass

	__have_asn1 = True
except ImportError:
	__have_asn1 = False

def have_asn1_support():
	return __have_asn1

def __assert_asn1_support():
	if not have_asn1_support():
		raise Exception("ASN.1 support is required, but the pyasn1 library could not be imported. Functionality not available.")

def parse_asn1_field_params_fp(derdata):
	"""Parse an ASN.1 DER encoded field parameter for fields in F_P."""
	__assert_asn1_support()
	(parsed, tail) = pyasn1.codec.ber.decoder.decode(derdata, asn1Spec = FieldFPParameters())
	return parsed

def parse_asn1_public_key(derdata):
	"""Parse an ASN.1 DER encoded EC public key."""
	__assert_asn1_support()
	(parsed, tail) = pyasn1.codec.ber.decoder.decode(derdata, asn1Spec = ECPublicKey())
	return parsed

def parse_asn1_private_key(derdata):
	"""Parse an ASN.1 DER encoded EC private key."""
	__assert_asn1_support()
	(parsed, tail) = pyasn1.codec.ber.decoder.decode(derdata, asn1Spec = ECPrivateKey())
	return parsed
