rule Table_Lookup_XOR
{
	meta:
		author = "Ashley"
		description = "this rule try to match a decode function using table to do replacement, used by NK"
		case = "N/A"
		hash0 = "00f850a82b366a2e4e0c312d1d7a1266"
		date = "2017/08/13"

	strings:

		$table = {FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 3E 00 FF FF FF FF FF FF 3F 00 34 00 35 00 36 00 37 00 38 00 39 00 3A 00 3B 00 3C 00 3D 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 00 01 00 02 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0C 00 0D 00 0E 00 0F 00 10 00 11 00 12 00 13 00 14 00 15 00 16 00 17 00 18 00 19 00 FF FF FF FF FF FF FF FF FF FF FF FF 1A 00 1B 00 1C 00 1D 00 1E 00 1F 00 20 00 21 00 22 00 23 00 24 00 25 00 26 00 27 00 28 00 29 00 2A 00 2B 00 2C 00 2D 00 2E 00 2F 00 30 00 31 00 32 00 33 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF}

		$function_snippet = {77 ?? FF 24 95 ?? ?? ?? ?? 02 C9 02 C9 88 0C 30 EB ?? 8B D1 C1 FA 04 08 14 30 46 C0 E1 04 88 0C 30 EB ?? 8B D1 C1 FA 02 08 14 30 46 C0 E1 06 88 0C 30 EB ?? 08 0C 30 46 45}


	condition:
		uint16(0) == 0x5A4D 
		and 
		($table or $function_snippet)

}


