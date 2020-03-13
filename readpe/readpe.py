import argparse
import pefile
import os
import sys
from tabulate import tabulate

def show_all_headers(pe):
	show_dos_header(pe)
	print()
	show_file_header(pe)
	print()
	show_optional_header(pe)
	print()
	show_data_directories(pe)

####################################################################################################################

def show_dos_header(pe):
	dos_header_table = []
	headers = ["Offset", "Name", "Value"]
	
	dos_dict = {"e_magic": "Magic number",
				"e_cblp": "Bytes on last page of file",
				"e_cp": "Pages in file",
				"e_crlc": "Relocations",
				"e_cparhdr": "Size of header in paragraphs",
				"e_minalloc": "Minimum extra paragraphs needed",
				"e_maxalloc": "Maximum extra paragraphs needed",
				"e_ss": "Initial (relative) SS value",
				"e_sp": "Initial SP value",
				"e_csum": "Checksum",
				"e_ip": "Initial IP value",
				"e_cs": "Initial (relative) CS value",
				"e_lfarlc": "File address of relocation table",
				"e_ovno": "Overlay number",
				"e_res": "Reserved words[4]",
				"e_oemid": "OEM identifier (for OEM information)",
				"e_oeminfo": "OEM information; OEM identifier specific",
				"e_res2": "Reserved words[10]",
				"e_lfanew": "File address of new exe header"}

	dos_header = pe.DOS_HEADER.dump_dict()
	
	for key, val in dos_header.items():
		if key == "Structure":
			continue
		elif key == "e_magic":
			dos_header_table.append([
				hex(val["FileOffset"]),
				dos_dict[key],
				hex(val["Value"])[2:] + " \"MZ\" ",
			])
		elif key == "e_res":
			dos_header_table.append([
				hex(val["FileOffset"]),
				dos_dict[key],
				str("0,"*4)[:-1]
			])
		elif key == "e_res2":
			dos_header_table.append([
				hex(val["FileOffset"]),
				dos_dict[key],
				str("0,"*10)[:-1]
			])
		else:
			dos_header_table.append([
				hex(val["FileOffset"]),
				dos_dict[key],
				hex(val["Value"]),
			])

	print("##############")
	print("# DOS_HEADER #")
	print("##############")
	print(tabulate(dos_header_table, headers, tablefmt="fancy_grid"))

####################################################################################################################

def show_file_header(pe):
	file_header_table = []
	headers = ["Offset", "Name", "Value", "Description"]

	file_header = pe.FILE_HEADER.dump_dict()

	for key, val in file_header.items():
		if key == "Structure":
			continue
		elif key == "Machine":
			file_header_table.append([
				hex(val["FileOffset"]), 
				key, 
				hex(val["Value"]),
				pefile.MACHINE_TYPE.get(val["Value"])
			])
		elif key == "NumberOfSections":
			file_header_table.append([
				hex(val["FileOffset"]), 
				key, 
				hex(val["Value"]),
				val["Value"]
			])
		elif key == "TimeDateStamp":
			file_header_table.append([
				hex(val["FileOffset"]), 
				key, 
				val["Value"][:10],
				val["Value"][12:-1]
			])
		elif key == "Characteristics":
			file_header_table.append([
				hex(val["FileOffset"]), 
				key, 
				hex(val["Value"]),
				val["Value"]
			])

			ch = val["Value"]
			ch_dict = pefile.IMAGE_CHARACTERISTICS.items()
			ch_dict = dict(list(ch_dict)[len(ch_dict)//2:])
			for chname, chval in ch_dict.items():
				if chval & ch > 0:
					file_header_table.append(["", "", hex(chval), chname])
		else:
			file_header_table.append([
				hex(val["FileOffset"]), 
				key, 
				hex(val["Value"]),
				val["Value"]
			])

	print("###############")
	print("# FILE_HEADER #")
	print("###############")
	print(tabulate(file_header_table, headers, tablefmt="fancy_grid"))

####################################################################################################################

def show_optional_header(pe):
	optional_header_table = []
	headers = ["Offset", "Name", "Value", "Description"]

	optional_header = pe.OPTIONAL_HEADER.dump_dict()

	for key, val in optional_header.items():
		if key == "Structure":
			continue
		elif key == "Magic":
			optional_header_table.append([
				hex(val["FileOffset"]),
				key,
				hex(val["Value"]),
				"NT32" if val["Value"] == 0x10b else "NT64" 
			])
		elif key == "Subsystem":
			optional_header_table.append([
				hex(val["FileOffset"]),
				key,
				hex(val["Value"]),
				pefile.SUBSYSTEM_TYPE.get(val["Value"])[16:]
			])
		elif key == "DllCharacteristics":
			optional_header_table.append([
				hex(val["FileOffset"]),
				key,
				hex(val["Value"]),
				val["Value"]
			])
			dll_char = val["Value"]
			char_dict = pefile.DLL_CHARACTERISTICS.items()
			char_dict = dict(list(char_dict)[len(char_dict)//2:])

			for dname, dval in char_dict.items():
				if dval & dll_char > 0:
					optional_header_table.append(["", "", hex(dval), dname])

		else:
			optional_header_table.append([
				hex(val["FileOffset"]),
				key,
				hex(val["Value"]),
				val["Value"]
			])

	print("###################")
	print("# OPTIONAL_HEADER #")
	print("###################")
	print(tabulate(optional_header_table, headers, tablefmt="fancy_grid"))

####################################################################################################################

def show_data_directories(pe):
	data_directory_table = []
	headers = ["Offset", "Data Directory", "Virtual Address", "Size"]

	for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
		data_directory_table.append([
			hex(data_directory.__file_offset__),
			data_directory.name,
			hex(data_directory.VirtualAddress),
			hex(data_directory.Size)
		])

	print("####################")
	print("# DATA_DIRECTORIES #")
	print("####################")
	print(tabulate(data_directory_table, headers, tablefmt="fancy_grid"))

####################################################################################################################

def show_imports(pe):
	if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress == 0:
		print("no imports found")
		return;

	import_table = []
	headers = ["Import Name", "DLL Name"]

	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll_name = entry.dll.decode("utf-8")
		for imp in entry.imports:
			if imp.name == None: import_name = "Ordinal: " + str(imp.ordinal)
			else: import_name = imp.name.decode("utf-8")
			import_table.append([import_name, dll_name])

	print("###########")
	print("# IMPORTS #")
	print("###########")
	print(tabulate(import_table, headers=headers, tablefmt="fancy_grid"))

####################################################################################################################

def show_exports(pe):
	if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress == 0:
		print("no exports found")
		return;

	export_table = []
	headers = ["Export Name", "Ordinal"]

	for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
		if exp.name == None: export_name = "None"
		else: export_name = exp.name.decode("utf-8")
		export_table.append([export_name, exp.ordinal])
	
	print("###########")
	print("# EXPORTS #")
	print("###########")
	print(tabulate(export_table, headers=headers, tablefmt="fancy_grid"))

####################################################################################################################

def show_sections(pe):
	section_table = []
	headers = ["Name", "Raw Addr.", "Raw Size", "Virtual Addr.", "Virtual Size", "Characteristics", "Flags", "Entropy"]

	for section in pe.sections:
		R = 'R' if (section.Characteristics & 0x40000000) > 0 else '-'
		W = 'W' if (section.Characteristics & 0x80000000) > 0 else '-'
		E = 'E' if (section.Characteristics & 0x20000000) > 0 else '-'

		section_table.append([
			section.Name.decode("utf-8").split('\x00')[0],	# dirty trick for malformed section names
			hex(section.PointerToRawData),
			hex(section.SizeOfRawData),
			hex(section.VirtualAddress),
			hex(section.Misc_VirtualSize),
			hex(section.Characteristics),
			R+W+E,
			section.get_entropy()
		])
		
	print("############")
	print("# SECTIONS #")
	print("############")
	print(tabulate(section_table, headers=headers, tablefmt="fancy_grid"))

####################################################################################################################

def show_resources(pe):
	if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress == 0:
		print("no resources found")
		return

	resource_table = []
	headers = ["Type", "Offset", "Size", "Query"]

	for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
		rsrc_type_str = pefile.RESOURCE_TYPE.get(rsrc.id, "RT_DATA")[3:]	# ignore RT_
		rsrc_type = str(rsrc.name) if rsrc.name != None else str(rsrc.id)

		for entry in rsrc.directory.entries:
			offset = entry.directory.entries[0].data.struct.OffsetToData
			size = entry.directory.entries[0].data.struct.Size
			entry_name = str(entry.name) if entry.name != None else str(entry.id)

			resource_table.append([
				rsrc_type_str,
				hex(offset),
				size,
				"--type " + rsrc_type + " --name " + entry_name
			])

	print("#############")
	print("# RESOURCES #")
	print("#############")
	print(tabulate(resource_table, headers, tablefmt="fancy_grid"))

####################################################################################################################

def extract_resources(pe, _type=None, _name=None):
	if (_type != None) and (_name != None):
		for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
			rsrc_type_str = pefile.RESOURCE_TYPE.get(rsrc.id, "RT_DATA")[3:]
			rsrc_type = str(rsrc.name) if rsrc.name != None else str(rsrc.id)

			if rsrc_type == _type:
				for entry in rsrc.directory.entries:
					entry_name = str(entry.name) if entry.name != None else str(entry.id)
					if entry_name == _name:
						offset = entry.directory.entries[0].data.struct.OffsetToData
						size = entry.directory.entries[0].data.struct.Size
						data = pe.get_data(offset, size)

						ico_header = b"\x00\x00\x01\x00\x01\x00\x20\x40\x00\x00\x01\x00\x04\x00\xE8\x02\x00\x00\x16\x00\x00\x00"
						if rsrc_type_str == "ICON": data = ico_header + data

						dump_name = (rsrc_type_str if rsrc.name == None else str(rsrc.name)) + "_" + entry_name
						with open(dump_name, "wb") as f: f.write(data)
						return
	print("please specify the resource type and name.")
	exit()

####################################################################################################################

class MyCustomParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        exit()

def main():
	formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=50)
	usage_msg = lambda : "readpe <pefile> <options>"
	parser = MyCustomParser(add_help=False,
							formatter_class=formatter,
							description=" Display information about the contents of PE files",
							epilog="Example: readpe test.exe -d -h -o",
							usage=usage_msg())

	parser.add_argument("pefile", help="PE file path")

	parser.add_argument("-H", "--all-headers", action='store_true', help="Display all PE headers")
	parser.add_argument("-d", "--dos-header", action="store_true", help="Display the PE DOS header")
	parser.add_argument("-h", "--file-header", action="store_true", help="Display the PE File header")
	parser.add_argument("-o", "--optional-header", action="store_true", help="Display the PE Optional header")
	parser.add_argument("-D", "--dirs", action="store_true", help="Display the PE Data Directories")

	parser.add_argument("-i", "--imports", action="store_true", help="Display imported functions")
	parser.add_argument("-e", "--exports", action="store_true", help="Display exported functions")

	parser.add_argument("-s", "--sections", action="store_true", help="Display all sections headers")

	parser.add_argument("-r", "--resources", action="store_true", help="Display all resources")
	parser.add_argument("-x", "--extract", action="store_true", help="Extract resources")
	parser.add_argument("-t", "--type", help="Resource type to dump")
	parser.add_argument("-n", "--name", help="Resource name to dump")

	parser.add_argument("--help", action="help", help="Display this help")

	args = parser.parse_args()
	if(len(sys.argv) == 2):
		parser.print_help()
		exit()

	file_path = args.pefile

	if not os.path.isfile(file_path):
		print("error: file doesn't exist")
		exit()

	try:
		pe = pefile.PE(file_path)
	except pefile.PEFormatError:
		print("error: not a PE file")
		exit()

	if args.all_headers:
		show_all_headers(pe)
	if args.dos_header:
		show_dos_header(pe)
	if args.file_header:
		show_file_header(pe)
	if args.optional_header:
		show_optional_header(pe)
	if args.dirs:
		show_data_directories(pe)
	if args.imports:
		show_imports(pe)
	if args.exports:
		show_exports(pe)
	if args.sections:
		show_sections(pe)
	if args.resources:
		show_resources(pe)
	if args.extract:
		extract_resources(pe, args.type, args.name)

if __name__ == '__main__':
    main()