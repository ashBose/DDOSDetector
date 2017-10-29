class Record(object):
	def __init__(self, ip_address, time_stamp):
		self._ip_address = ip_address
		self._time_stamp = time_stamp

	@property
	def ip_address(self):
		return self._ip_address

	@property
	def time_stamp(self):
		return self._time_stamp

	@ip_address.setter
	def ip_address(self, ip_address):
		self._ip_address = ip_address

	@time_stamp.setter
	def time_stamp(self, time_stamp):
		self._time_stamp = time_stamp
