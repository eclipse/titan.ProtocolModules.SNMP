/******************************************************************************
* Copyright (c) 2013, 2014  Ericsson AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v1.0
* which accompanies this distribution, and is available at
* http://www.eclipse.org/legal/epl-v10.html
*
* Contributors:
*   Endre Kulcsar - initial implementation and initial documentation
******************************************************************************/
//
//  File:               SNMP_USM.cc
//  Description:        SNMP protocol module external functions for encryption
//  Rev:                R2B
//  Prodnr:             CNL 113 774
//

#include "SNMP_Functions.hh"
#include "openssl/md5.h"
#include "openssl/des.h"

// snmpEngineBoots shall be a 32-bit integer value
// this is the first 4 octets of the salt
#define snmpEngineBoots 45646

// this is the last 4 octets of the salt
#define local32bitint 248795
using namespace SNMPmsg__Types;

namespace SNMP__Functions{

OCTETSTRING calculate__MD5__MAC(const OCTETSTRING& authKey, 
	const SNMPv3__Message& wholeMsg) {
	
	if (authKey.lengthof() != 16)
		TTCN_error("SNMPv3USM: authKey's length must be 16.");

	SNMPv3__Message wholeMsg_copy = SNMPv3__Message(wholeMsg);
	
	// RFC 3414, section 6.3.1
	
	const OCTETSTRING& extendedAuthKey = authKey + OCTETSTRING(48, 
		(const unsigned char*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
		"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
	
	const OCTETSTRING& IPAD = OCTETSTRING(64, (const unsigned char*)
		"\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36"
		"\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36"
		"\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36"
		"\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36\x36"
	);
	const OCTETSTRING& K1 = extendedAuthKey ^ IPAD;
	
	const OCTETSTRING& OPAD = OCTETSTRING(64, (const unsigned char*)
		"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"
		"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"
		"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"
		"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"
	);
	
	const OCTETSTRING& K2 = extendedAuthKey ^ OPAD;
	
	TTCN_Buffer buf;
	
	wholeMsg_copy.encode(SNMPv3__Message_descr_, buf, TTCN_EncDec::CT_BER,
		BER_ENCODE_DER);
	
	const OCTETSTRING& encoded_msg_without_auth = OCTETSTRING(buf.get_len(), 
		buf.get_data());
	
	const OCTETSTRING& K1_plus_msg = K1 + encoded_msg_without_auth;

	unsigned char first_md5_digest[MD5_DIGEST_LENGTH];	
	MD5((const unsigned char*)K1_plus_msg, K1_plus_msg.lengthof(), first_md5_digest);

	const OCTETSTRING& K2_plus_first_digest = K2 + OCTETSTRING(MD5_DIGEST_LENGTH, (const unsigned char*)first_md5_digest);

	unsigned char final_md5_digest[MD5_DIGEST_LENGTH];
	MD5((const unsigned char*)K2_plus_first_digest, K2_plus_first_digest.lengthof(), final_md5_digest);
	
	return OCTETSTRING(12, (const unsigned char*)final_md5_digest);
	
}

void encryptData (const OCTETSTRING& encryptKey, const ScopedPDU& dataToEncrypt,
	OCTETSTRING& encryptedData, const OCTETSTRING& privParameters) {
	
	const OCTETSTRING& des_key = OCTETSTRING(8, (const unsigned char*)encryptKey);
	
	const OCTETSTRING& pre_IV = OCTETSTRING(8, (const unsigned char*)encryptKey + 8);
	
	const OCTETSTRING& salt = privParameters;
	
	const OCTETSTRING& IV = pre_IV ^ salt; // privParameters is the "salt"
	
	TTCN_Buffer buf;
	
	dataToEncrypt.encode(ScopedPDU_descr_, buf, TTCN_EncDec::CT_BER,
		BER_ENCODE_DER);
	
	DES_cblock key;
	DES_key_schedule schedule;
	memcpy(key, (const unsigned char*)des_key, 8);
	DES_key_sched(&key, &schedule);
	DES_set_key_checked(&key, &schedule); // error check needed
	
	DES_cblock ivec;
	memcpy(ivec, (const unsigned char*)IV, 8);
	
	int out_len;
	
	if (buf.get_len() % 8 == 0)
		out_len = buf.get_len();
	else
		out_len = (buf.get_len()/8 + 1) * 8;
	
	unsigned char* encr_buf = new unsigned char [out_len];
	
	DES_ncbc_encrypt(buf.get_data(), encr_buf, buf.get_len(), &schedule, 
		&ivec, DES_ENCRYPT);

	encryptedData = OCTETSTRING(out_len, encr_buf);

	delete [] encr_buf;
};

void decryptData (const OCTETSTRING& decryptKey, const OCTETSTRING& privParameters, 
	const OCTETSTRING& encryptedData, ScopedPDU& decryptedData) {

	const OCTETSTRING& des_key = OCTETSTRING(8, (const unsigned char*)decryptKey);
	
	const OCTETSTRING& pre_IV = OCTETSTRING(8, (const unsigned char*)decryptKey + 8);
	
	const OCTETSTRING& salt = privParameters;
	
	const OCTETSTRING& IV = pre_IV ^ salt; // privParameters is the "salt"
	
	DES_cblock key;
	DES_key_schedule schedule;
	memcpy(key, (const unsigned char*)des_key, 8);

	DES_set_odd_parity(&key);

	int setkey_res = DES_set_key_checked(&key, &schedule); // error check needed
	
	switch (setkey_res) {
	case 0:
		break;
	case -1:
		TTCN_warning("SNMPv3USM: parity error in DES key.");
		break;
	case -2:
		TTCN_warning("SNMPv3USM: weak DES key.");
	default: 
		TTCN_warning("SNMPv3USM: unknown result code of DES_set_key.");
	}
	
	DES_cblock ivec;
	memcpy(ivec, (const unsigned char*)IV, 8);
	
	unsigned char* decr_buf = new unsigned char [encryptedData.lengthof()];
	
	DES_ncbc_encrypt((const unsigned char*)encryptedData, decr_buf,
		encryptedData.lengthof(), &schedule, &ivec, DES_DECRYPT);

	TTCN_Buffer buf;
	
	buf.put_os(OCTETSTRING(encryptedData.lengthof(), decr_buf));
	
	decryptedData.decode(ScopedPDU_descr_, buf, TTCN_EncDec::CT_BER, 
		BER_ACCEPT_ALL);

	delete [] decr_buf;
}

void password__to__key__md5(const OCTETSTRING& password, const OCTETSTRING& engineID,
	OCTETSTRING& key) {
	
	if(password.lengthof()==0) TTCN_error("SNMPv3USM: The function password_to_key_md5 has been called with 0 length password");
        const unsigned char* password_p = (const unsigned char*)password;
	unsigned int passwordlen = password.lengthof();
	        
	const unsigned char* engineID_p = (const unsigned char*) engineID;
	unsigned int engineLength = engineID.lengthof();
	
	unsigned char key_buf[16];

	MD5_CTX MD;
	unsigned char *cp, password_buf[64];
	unsigned long int password_index = 0;
	unsigned long int count = 0, i;

	MD5_Init (&MD);   /* initialize MD5 */

	/**********************************************/
	/* Use while loop until we've done 1 Megabyte */
	/**********************************************/
	while (count < 1048576) {
		cp = password_buf;
		for (i = 0; i < 64; i++) {
    		/*************************************************/
    		/* Take the next octet of the password, wrapping */
    		/* to the beginning of the password as necessary.*/
    		/*************************************************/
    		*cp++ = password_p[password_index++ % passwordlen];
		}
		MD5_Update (&MD, password_buf, 64);
		count += 64;
	}
	MD5_Final (key_buf, &MD);          /* tell MD5 we're done */

	/*****************************************************/
	/* Now localize the key with the engineID and pass   */
	/* through MD5 to produce final key                  */
	/* May want to ensure that engineLength <= 32,       */
	/* otherwise need to use a buffer larger than 64     */
	/*****************************************************/
	memcpy(password_buf, key_buf, 16);
	memcpy(password_buf+16, engineID_p, engineLength);
	memcpy(password_buf+16+engineLength, key_buf, 16);

	MD5_Init(&MD);
	MD5_Update(&MD, password_buf, 32+engineLength);
	MD5_Final(key_buf, &MD);
	
	key = OCTETSTRING(16, key_buf);
	
	return;
	}

OCTETSTRING enc__UsmSecurityParameters(const UsmSecurityParameters& input) {
	
	TTCN_Buffer buf;
	input.encode(UsmSecurityParameters_descr_, buf, TTCN_EncDec::CT_BER,
		BER_ENCODE_DER);
	return OCTETSTRING(buf.get_len(), buf.get_data());
}

UsmSecurityParameters dec__UsmSecurityParameters(const OCTETSTRING& input) {
	TTCN_Buffer buf;
	buf.put_os(input);
	UsmSecurityParameters decoded;
	decoded.decode(UsmSecurityParameters_descr_, buf, TTCN_EncDec::CT_BER,
		BER_ACCEPT_ALL);
	return decoded;
}

TTCN_Module SNMPv3USM("SNMPv3USM", __DATE__, __TIME__);
}
