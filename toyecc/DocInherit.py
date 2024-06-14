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

def doc_inherit(superclass):
	"""Inherit the docstring of a parent method. The super class needs to be
	given as the decorator's parameter. Does not overwrite the docstring if
	there is already one present."""
	def decorator(decoree):
		method_name = decoree.__name__
		if decoree.__doc__ is None:
			parent_method = getattr(superclass, method_name, None)
			if parent_method is None:
				raise Exception("Tried to inherit docstring of method '%s' from class '%s', but the latter does not offer a method by that name." % (method_name, str(superclass)))
			docstr = parent_method.__doc__			
			if docstr is None:
				raise Exception("Tried to inherit docstring of method '%s' from class '%s', but that method also does not have a docstring." % (method_name, str(superclass)))
			decoree.__doc__ = docstr
		else:
			raise Exception("Tried to overwrite an already present docstring of %s" % (str(decoree)))
		return decoree
	return decorator
