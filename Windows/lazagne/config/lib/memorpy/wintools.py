# Author: Nicolas VERDIER
# This file is part of memorpy.
#
# memorpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# memorpy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with memorpy.  If not, see <http://www.gnu.org/licenses/>.

from ctypes import windll
import time

def start_winforeground_daemon():
	import threading
	t=threading.Thread(target=window_foreground_loop)
	t.daemon=True
	t.start()

def window_foreground_loop(timeout=20):
	""" set the windows python console to the foreground (for example when you are working with a fullscreen program) """
	hwnd = windll.kernel32.GetConsoleWindow()
	HWND_TOPMOST 	= -1 
	SWP_NOMOVE 		= 2
	SWP_NOSIZE 		= 1
	while True:
		windll.user32.SetWindowPos(hwnd, HWND_TOPMOST, 0,0,0,0, SWP_NOMOVE | SWP_NOSIZE)
		time.sleep(timeout)
	