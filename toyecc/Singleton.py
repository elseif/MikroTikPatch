#!/usr/bin/python3
#
#	Singleton - Singleton decorator, taken from PEP318
#	Copyright (C) 2011-2022 Johannes Bauer
#
#	This file is part of jpycommon.
#
#	jpycommon is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	jpycommon is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with jpycommon; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#
#	File UUID a24a2230-7bd4-4737-98ab-8aae62d1bd57

def singleton(cls):
	class InnerClass(cls):
		_instance = None

		def __new__(cls, *args, **kwargs):
			if InnerClass._instance is None:
					InnerClass._instance = super(InnerClass, cls).__new__(cls, *args, **kwargs)
					InnerClass._instance._initialized = False
			return InnerClass._instance

		def __init__(self, *args, **kwargs):
			if self._initialized:
				return
			super(InnerClass, self).__init__(*args, **kwargs)
			self._initialized = True

	InnerClass.__name__ = cls.__name__
	return InnerClass


if __name__ == "__main__":
	print("start")

	@singleton
	class FooSingleton():
		_barkoo = -1

		def __init__(self):
			print("init called")

		def getid(self):
			return id(self) * FooSingleton._barkoo

	print("pre init")
	x = FooSingleton()
	print(x, x.getid())

	y = FooSingleton()
	print(y, y.getid())

	z = FooSingleton()
	print(z, z.getid())

	assert(x is y)
