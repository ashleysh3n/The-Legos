rule asdfDoor
{
	meta:
		author = "Ashley"
		description = "this rule try to match backdoor asdfDoor used by North Korea"
		hash0 = "7caa500b60a536d7501e7a6c02408538"
		date = "2017/08/09"

	strings:
		$mapping = "asdfazxvczxvczxvadsf4"

		$string_2 = "rNHayCabG60jyw=="                    
		$string_3 = "rdHNzQ=="                            
		$string_4 = "rNHA3z2X"                            
		$string_5 = "vNvA1SybBA=="                        
		$string_6 = "rNHA3w=="                            
		$string_7 = "rNHC3iqM"                            
		$string_8 = "vNjByCyLH6E42mY="                    
		$string_9 = "lsTG1zmZAKt9235n"                    
		$string_10 = "mNHa+i2ZALY2zWFCxQyJ"                
		$string_11 = "mNHa6yyKMaYyz2Zu2SOI88M="            
		$string_12 = "ntDY2jmRQ/B9235n"                    
		$string_13 = "jdHJ9DmdHok2xldz6g=="                
		$string_14 = "jdHJ6jydArsF3n5+zi+e1A=="            
		$string_15 = "jdHJ+CWXA6cY2ms="                    
		$string_16 = "jdHJ+DudEbY29Hdy7hKn"                
		$string_17 = "jdHJ6CyMJqM/yndO0ys="                
		$string_18 = "jdHJ/yyUFbY26XNn3g+n"                
		$string_19 = "jdHJ6jydArsa0XRk4A+f1A=="            
		$string_20 = "jdHJ/ieNHZQy02du6g=="                
		$string_21 = "jdHJ/ieNHYk2xldz6g=="                
		$string_22 = "jdHJ6CyMO6cq7Hdo3hiP4dU="            
		$string_23 = "nMbXyz25E7Mm1mBu6AWI4ckazlk="        
		$string_24 = "nMbXyz2xHbI8zWZAzhM="                
		$string_25 = "nMbXyz2qFa423mFu6AWI4ckazg=="        
		$string_26 = "nMbXyz29HqEhxmJ/"                    
		$string_27 = "nMbXyz28FbEnzX1y4A+f"                
		$string_28 = "nMbXyz28FaEhxmJ/"                    
		$string_29 = "nMbXyz27Aqcyy3dDyhmO"                
		$string_30 = "nMbXyz2wEbE7+3N/yg=="                
		$string_31 = "nMbXyz28FbEnzX1y4wuV/Q=="            
		$string_32 = "nMbXyz28FbA6yXdAzhM="                
		$string_33 = "kMTL1Rq7PaM93nVu2Ss="                
		$string_34 = "kMTL1RqdArQ63HdK"                    
		$string_35 = "jsHLyTCrFbAl1nFu+B6H4dkR"            
		$string_36 = "nNvAzzuXHJE2zWRiyA8="                
		$string_37 = "mNHa7jqdAowy0ndK"                    
		$string_38 = "qN3A0iedBOw3034="                    
		$string_39 = "ltra3juWFbYcz3dl6g=="                
		$string_40 = "ltra3juWFbYcz3dl/hiK1A=="            
		$string_41 = "ltra3juWFbYQ0HxlzgmS1A=="            
		$string_42 = "l8DaywaIFawB2mN+zhmS1A=="            
		$string_43 = "ltra3juWFbYQ0314ziKH+8gO3w=="        
		$string_44 = "ltra3juWFbYA2mZIxAWN/Mkj"            
		$string_45 = "ltra3juWFbYQzXNowD+U+e0="            
		$string_46 = "ltra3juWFbYB2nNv7QOK8A=="            
		$string_47 = "l8DayxqdHqYB2mN+zhmS1A=="            
		$string_48 = "l8DayxiNFbAq9nxtxCs="                
		$string_49 = "l8DaywicFJA2zmdu2B6u8M0G32pl4A=="    
		$string_50 = "l8DayxqdHqYB2mN+zhmS0NQj"            
		$string_51 = "ltra3juWFbYEzXt/ziyP+ck="            
		$string_52 = "l8DaywyWFJA2zmdu2B6n"                
		$string_53 = "m9HC3j2dJbA//HNoww+j+9gQww=="        
		$string_54 = "ltra3juWFbYU2mZIxASI8M8W33xF1WRRfg=="


	condition:
		uint16(0) == 0x5A4D 
		and 
		$mapping
		and 
		(20 of ($string_*))
}