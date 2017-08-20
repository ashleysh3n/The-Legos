rule S_Encoding
{
	meta: 
		author = "Ashley Shen"
		description = "Detect the encoding API strings used in Phandoor and other malware from North Korea's Andariel group"
		sample_hash = "396adbedc6296e8a3f6ddd4eb6e851b4"

	strings: 
		$string1 = "S^WSAIoctl"
		$string2 = "S^setsockopt"
		$string3 = "S^select"
		$string4 = "S^connect"
		$string5 = "S^recv"
		$string6 = "S^send"
		$string7 = "S^sendto"
		$string8 = "S^GetModuleFileNameA"
		$string9 = "S^DeleteFileA"
		$string10 = "S^CreateMutexA"
		$string11 = "S^CreateThread"
		$string12 = "S^CreateFileA"
		$string13 = "S^GetFileSize"
		$string14 = "S^LockFile"
		$string15 = "S^WaitForSingleObject"
		$string16 = "S^ReleaseMutex"
		$string17 = "S^UnlockFile"
		$string18 = "S^CloseHandle"

	condition: 
		10 of them
}