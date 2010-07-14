module WSS4R
module Security
module Xml

class SignatureValue
	def initialize(security_token)
		@security_token = security_token
	end
		
	def process(document, signature)
		canonicalizer = TransformerFactory::get_instance("http://www.w3.org/2001/10/xml-exc-c14n#")
		#esult = canonicalizer.write_document_node(@signed_info) #Broken
		signed_info = XPath.first(signature, "//SignedInfo")
		result = canonicalizer.canonicalize_element(signed_info)
		signature_value = @security_token.sign_b64(result)
		signature_value_element = signature.add_element(Names::SIGNATURE_VALUE)
		signature_value.strip!
		signature_value_element.text=(signature_value)

		signed_info
	end
end

end #Xml
end #Security
end #WSS4R