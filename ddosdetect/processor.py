from datetime import datetime
from hits import HitStructure
from record import Record


class AttackDetector(object):
	def __init__(self, logging):
		self.logging = logging

	@staticmethod
	def calculate_time_difference(last_hit_time, current_time):
		try:
			difference = datetime.strptime(current_time, '%H:%M:%S') - \
			             datetime.strptime(last_hit_time, '%H:%M:%S')
			difference = difference.seconds * 1000
		except TypeError, e:
			raise e
		finally:
			return difference

	def load_input(self, input_file):
		record_list = []
		try:
			with open(input_file, 'r') as fp:
				for line in fp:
					# sends each line of the file to the split function in order to
					# populate the Record data structure from the required fields
					# of the record in the actual file
					record = self.split_fields(line)
					record_list.append(record)
		except IOError, e:
			self.logging.error(e)
		finally:
			return record_list

	def fraud_detection(self, record_list, threshold):

		"""
		map_of_records:
		responsible for maintaining the count of seen IP's in the current
		2minute window

		"""
		map_of_records = {}
		suspicious_ips = set()  # responsible for mainitaining the suspicious IPs

		"""
			1.If IP not in map, add a new entry into the map with the following data:
				Key : IP
				Value : Hit Structure [timestamp:timestampOfTheIP,count:1]
			2.If IP in map,check whether the timestamp is within the last 30 secs
				a.If yes, increment the count value in the Hit Structure by 1
				b.If no, update the entry in the map with the timestamp of this 
				IP and resetting the count to 1.
			3.If the count exceeds the threshold, add it to the set of suspicious IPs

		"""

		for record in record_list:
			ip_address = record.ip_address
			current_time = record.time_stamp
			# Implements step 2. of the above algorithm
			if ip_address in map_of_records:
				last_hit_time = map_of_records[ip_address]. \
					time_stamp  # fetches the last
				# timestamp this IP was seen in the 2 minute window
				difference = self.calculate_time_difference(
					last_hit_time,
					current_time)
				# calculates the difference between current record and
				# last seen same IP record
				self.logging.info("{} Difference :{}".format(
					ip_address,
					difference))
				diff_seconds = int(difference / 1000 % 60)
				diff_minutes = int(difference / (60 * 1000) % 60)
				diff_hours = int(difference / (60 * 60 * 1000))
				if diff_hours == 0 and diff_minutes == 0 and diff_seconds <= 30:
					update_count = map_of_records[ip_address].count
					map_of_records[ip_address].count = update_count + 1
					# Implements step 3 of the above algortihm
					if update_count + 1 >= threshold:
						if ip_address not in suspicious_ips:
							suspicious_ips.add(ip_address)
				#else:
					#map_of_records[ip_address].time_stamp = last_hit_time
			# Implements step 1 of the above algorithm
			else:
				map_of_records[ip_address] = HitStructure(current_time, 1)
		return suspicious_ips

	@staticmethod
	def write_output(suspicious_ips, output_file):
		with open(output_file, 'w') as file_handler:
			# Write the unique list of suspicious IP's onto a different file
			for ip in suspicious_ips:
				file_handler.write(ip + "\n")

	@staticmethod
	def split_fields(line):
		# Function to accept a line and populate the Record Data Structure
		# for easy access
		fields = line.split(' ')
		timestamp = fields[3].split(":", 1)[1].split(" ", 1)[0]
		return Record(fields[0], timestamp)
