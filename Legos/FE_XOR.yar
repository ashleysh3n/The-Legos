rule FE_XOR
{
	meta:
		author = "Ashley Shen"
		description = "this rule try to match FE_XOR function used in trojan Phandoor and Andariel group's malware"
		hash0 = "5ecc2b2f4b6fc842dc1b501e277096c7"
		date = "2017/08/04"

	strings:
		/*
		004015BA  |. 8BD9           |MOV EBX,ECX
		004015BC  |. C1EA 08        |SHR EDX,8
		004015BF  |. C1EB 10        |SHR EBX,10
		004015C2  |. 22DA           |AND BL,DL
		004015C4  |. 22D9           |AND BL,CL
		004015C6  |. 8BC8           |MOV ECX,EAX
		004015C8  |. C1E9 10        |SHR ECX,10
		004015CB  |. 224D F8        |AND CL,BYTE PTR SS:[EBP-8]
		*/

		$xor_func_snipet1={8B D9 C1 EA 08 C1 EB 10 22 DA 22 D9 8B C8 C1 E9 10 22 4D F8}

		/*
		004015CE  |. 8955 F0        |MOV DWORD PTR SS:[EBP-10],EDX
		004015D1  |. 8AD0           |MOV DL,AL
		004015D3  |. 2255 FF        |AND DL,BYTE PTR SS:[EBP-1]
		004015D6  |. 32D9           |XOR BL,CL
		004015D8  |. C1E8 18        |SHR EAX,18
		004015DB  |. 8D0C3F         |LEA ECX,DWORD PTR DS:[EDI+EDI]
		004015DE  |. 33CF           |XOR ECX,EDI
		004015E0  |. 32D3           |XOR DL,BL
		004015E2  |. 32D0           |XOR DL,AL
		004015E4  |. 8B45 F4        |MOV EAX,DaWORD PTR SS:[EBP-C]
		004015E7  |. 81E1 FE010000  |AND ECX,1FE
		004015ED  |. C1E0 18        |SHL EAX,18
		004015F0  |. 0B45 F8        |OR EAX,DWORD PTR SS:[EBP-8]
		004015F3  |. C1E1 16        |SHL ECX,16
		*/

		$xor_func_snipet2={89 55 F0 8A D0 22 55 FF 32 D9 C1 E8 18 8D 0C 3F 33 CF 32 D3 32 D0 8B 45 F4 81 E1 FE 01 00 00 C1 E0 18 0B 45 F8 C1 E1 16 }

	condition:
		all of them
}