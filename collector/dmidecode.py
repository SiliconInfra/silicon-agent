import re
from shutil import which
from subprocess import check_output, PIPE


class DMI(object):
	def __init__(self):
		self.handle_re = re.compile('^Handle\\s+(.+),\\s+DMI\\s+type\\s+(\\d+),\\s+(\\d+)\\s+bytes$')
		self.in_block_re = re.compile('^\\t\\t(.+)$')
		self.record_re = re.compile('\\t(.+):\\s+(.+)$')
		self.record2_re = re.compile('\\t(.+):$')

		_type2str = {
			0: 'BIOS',
			1: 'System',
			2: 'Baseboard',
			3: 'Chassis',
			4: 'Processor',
			5: 'Memory Controller',
			6: 'Memory Module',
			7: 'Cache',
			8: 'Port Connector',
			9: 'System Slots',
			10: ' On Board Devices',
			11: ' OEM Strings',
			12: ' System Configuration Options',
			13: ' BIOS Language',
			14: ' Group Associations',
			15: ' System Event Log',
			16: ' Physical Memory Array',
			17: ' Memory Device',
			18: ' 32-bit Memory Error',
			19: ' Memory Array Mapped Address',
			20: ' Memory Device Mapped Address',
			21: ' Built-in Pointing Device',
			22: ' Portable Battery',
			23: ' System Reset',
			24: ' Hardware Security',
			25: ' System Power Controls',
			26: ' Voltage Probe',
			27: ' Cooling Device',
			28: ' Temperature Probe',
			29: ' Electrical Current Probe',
			30: ' Out-of-band Remote Access',
			31: ' Boot Integrity Services',
			32: ' System Boot',
			33: ' 64-bit Memory Error',
			34: ' Management Device',
			35: ' Management Device Component',
			36: ' Management Device Threshold Data',
			37: ' Memory Channel',
			38: ' IPMI Device',
			39: ' Power Supply',
			40: ' Additional Information',
			41: ' Onboard Devices Extended Information',
			42: ' Management Controller Host Interface'
		}

		self.str2type = {}
		for type_id, type_str in _type2str.items():
			self.str2type[type_str] = type_id

	def __str__(self):
		return "dmidecode"

	def _get_binary(self):
		return which(self.__str__())

	def _check_installation(self):
		return self._get_binary() is not None

	def command(self, run_with_sudo=False):
		if not self._check_installation():
			message = "{} not found".format(self.__str__())
			raise Exception(message)

		if run_with_sudo:
			return check_output(["sudo", self._get_binary()], stderr=PIPE)
		return check_output([self._get_binary()], stderr=PIPE)

	def parse(self, buffer):
		output_data = {}
		if isinstance(buffer, bytes):
			buffer = buffer.decode("utf-8")

		split_output = buffer.split("\n\n")
		for record in split_output:
			record_element = record.splitlines()

			# Entries with less than 3 lines are incomplete / inactive; skip them
			if len(record_element) < 3:
				continue

			handle_data = self.handle_re.findall(record_element[0])
			if not handle_data:
				continue

			handle_data = handle_data[0]
			dmi_handle = handle_data[0]
			output_data[dmi_handle] = {}
			output_data[dmi_handle]['DMIType'] = int(handle_data[1])
			output_data[dmi_handle]['DMISize'] = int(handle_data[2])
			output_data[dmi_handle]['DMIName'] = record_element[1]

			in_block_element = ''
			in_block_list = ''

			for i in range(2, len(record_element), 1):
				if i >= len(record_element):
					break

				# Check whether we are inside a \t\t block
				if in_block_element != '':
					in_block_data = self.in_block_re.findall(record_element[i])
					if in_block_data:
						if not in_block_list:
							in_block_list = [in_block_data[0]]
						else:
							in_block_list.append(in_block_data[0])

						output_data[dmi_handle][in_block_element] = in_block_list
						continue
					else:
						# We are out of the \t\t block; reset it again, and let
						# the parsing continue
						in_block_element = ''

				record_data = self.record_re.findall(record_element[1])
				if record_data:
					output_data[dmi_handle][record_data[0][0]] = record_data[0][1]
					continue

				record_data2 = self.record2_re.findall(record_element[i])
				if record_data2:
					#  This is an array of data - let the loop know we are inside
					#  an array block
					in_block_element = record_data2[0]
					in_block_list = ''
					continue

		if not output_data:
			raise Exception("Unable to parse {}".format(self.__str__()))
		return output_data

	def get_by_type(self, data, type_id):
		if isinstance(type_id, str):
			type_id = self.str2type.get(type_id)
			if type_id is None:
				return None

		result = []
		for entry in data.values():
			if entry["DMIType"] == type_id:
				result.append(entry)

		return result
