module WSS4R
module Security
module Util

class Names
	HEADER = "env:Header"
	SECURITY = "wsse:Security"
	BODY = "env:Body"
	ENCRYPTED_DATA = "xenc:EncryptedData"
	ENCRYPTION_METHOD = "xenc:EncryptionMethod"
	CIPHER_DATA = "xenc:CipherData"
	CIPHER_VALUE = "xenc:CipherValue"
	ENCRYPTED_KEY = "xenc:EncryptedKey"
	KEY_INFO = "KeyInfo"
	SECURITY_TOKEN_REFERENCE = "wsse:SecurityTokenReference"
	KEY_IDENTIFIER = "wsse:KeyIdentifier"
	REFERENCE_LIST = "xenc:ReferenceList"
	DATA_REFERENCE = "xenc:DataReference"
	REFERENCE_WSSE = "wsse:Reference"
	REFERENCE_DS = "Reference"
	SIGNATURE_VALUE = "SignatureValue"
	SIGNATURE = "Signature"
	CANONICALIZATION_METHOD = "CanonicalizationMethod"
	SIGNATURE_METHOD = "SignatureMethod"
	TRANSFORMS = "Transforms"
	TRANSFORM = "Transform"
	DIGEST_METHOD = "DigestMethod"
	DIGEST_VALUE = "DigestValue"
	BINARY_SECURITY_TOKEN = "wsse:BinarySecurityToken"
	SIGNED_INFO="SignedInfo"
  TIMESTAMP = "wsu:Timestamp"
  CREATED = "wsu:Created"
  EXPIRES = "wsu:Expires"
end

end #Util
end #Security
end #WSS4R