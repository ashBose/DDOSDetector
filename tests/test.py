import os
import unittest
import logging
from ddosdetect.processor import AttackDetector
from ddosdetect.record import Record


class AttackDetectorTests(unittest.TestCase):
	def setUp(self):
		self.inputData = os.path.join(os.path.dirname(__file__), 'testData.txt')
		self.outputPath = os.path.join(os.path.dirname(__file__),'testSuspicious.txt')
		logging.basicConfig(level=logging.DEBUG,
		                    format='%(asctime)s %(levelname)-8s %(message)s',
		                    datefmt='%a, %d %b %Y %H:%M:%S',
		                    filename='ddos.log',
		                    filemode='w')
		self.test_obj = AttackDetector(logging)

	def tearDown(self):
		try:
			os.remove(self.outputPath)
		except OSError as oserr:
			logging.error(oserr)

	def test_load_input(self):
		logging.basicConfig(level=logging.DEBUG,
		                    format='%(asctime)s %(levelname)-8s %(message)s',
		                    datefmt='%a, %d %b %Y %H:%M:%S',
		                    filename='ddos.log',
		                    filemode='w')
		self.assertEqual(len(self.test_obj.load_input(self.inputData)), 803)

	def test_fraud_detection(self):
		record_list = self.test_obj.load_input(self.inputData)
		self.assertEqual(self.test_obj.fraud_detection(record_list, 87), set(
			["211.188.214.36", "118.133.241.175", "238.164.11.148", "73.173.0.163",
			 "240.163.130.99"]))

	def test_calculate_time_difference(self):
		self.assertEqual(self.test_obj.calculate_time_difference(
			'23:03:15', '23:07:15'),
			240000)

	def test_split_fields(self):
		r = self.test_obj.splitFields("200.4.91.190 - - [25/May/2015:23:11:15 +0000] "
		                              "\"GET / HTTP/1.0\" 200 3557 \"-\" \"Mozilla/4.0 "
		                              "(compatible; MSIE 6.0; Windows NT 5.1; SV1)")
		self.assertIsInstance(r, Record)


if __name__ == '__main__':
	unittest.main()
