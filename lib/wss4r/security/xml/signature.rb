module WSS4R
module Security
module Xml
	
class Signature
	def initialize(security_token)
		@security_token = security_token
	end
	
	def process(document, signing_path)
	  signing_path ||= SOAPParser::BODY
	  doc = document
	  doc = XPath.first(document, signing_path).document() if signing_path	  
	  SOAPParser.document = doc

    security = Security.new()
    # signature_element = security.process(document, signing_path)
				
        # p signature_element.class
    # p security.to_s
    # security_token = @security_token.process(document)
    # children = security.children()
		#children.each{|child|
		#	security.delete(child)
		#}		
    # security.add_element(security_token) # TODO add inside key info
    signature_element = Document.new().add_element(Names::SIGNATURE)
		#children.each{|child|
		#	security.add_element(child)
		#}
    signature_element.add_namespace("xmlns:ds", Namespaces::DS)
    
    # p signature_element.to_s
    
# p signature_element
# debugger
		signed_info = SignedInfo.new([ signing_path ])
    signed_info.process(doc, signature_element)

    # p security.to_s

    signature_value = SignatureValue.new(@security_token)
    
    signature_value.process(doc, signature_element)

    # p security.to_s
    
		key_info = KeyInfo.new(@security_token, KeyInfo::KEY_IDENTIFIER)
		key_info.process(signature_element)#get_xml(signature_element)

    append_to = if signing_path == SOAPParser::BODY
                  XPath.first(document, SOAPParser::HEADER)
                else
                  XPath.first(doc, signing_path).parent
                end
                
		append_to.add_element(signature_element)
		
		document
	end

	def unprocess(document, path)
	  path ||= SOAPParser::BODY
	  doc = XPath.first(document, path)
	  if path == SOAPParser::BODY
	    signature_path = XPath.first(document, SOAPParser::HEADER)
    else
      signature_path = doc.parent
    end
	  signature = XPath.first(signature_path, "//Signature") # remove signature from doc to allow checking the hashes and everything
	  	  	  
    # SOAPParser.document = doc
    # p doc.to_s
	  
		@signature_value = XPath.first(signature, "//SignatureValue").text().gsub("\n","") 
		key_info = XPath.first(signature, "//KeyInfo")
    # p "*" * 10
    # p key_info
    # debugger
		@key_info = KeyInfo.new(key_info)
		@signed_info = SignedInfo.new()
		@signed_info.unprocess(doc, signature)
		@signature = signature
		@doc = doc
	end
	
	def verify_signature()
		signed_info = XPath.first(@signature, "//SignedInfo")
		inclusive_namespaces = XPath.first(signed_info, "//CanonicalizationMethod/InclusiveNamespaces")
		prefix_list = inclusive_namespaces.attribute("PrefixList") if (inclusive_namespaces)
		if (prefix_list)
			prefix_list = prefix_list.value().split()
		end
		transformer = TransformerFactory::get_instance(@signed_info.canonicalizer_method())
		transformer.prefix_list=(prefix_list)
		result = transformer.canonicalize_element(signed_info)
		signature_value = Base64.decode64(@signature_value)#.strip()
		public_key = @key_info.security_token().certificate().public_key()
		#TODO: check certificate
		certificate = @key_info.security_token().certificate()

		verify = public_key.verify(OpenSSL::Digest::SHA1.new(), signature_value, result)
		raise FaultError.new(VerificationFault.new()) if !(verify)
		certitificate = @key_info.security_token().certificate()
	end

	def verify()
		@signed_info.verify()
		verify_signature()
	end
end

end #Xml
end #Security
end #WSS4R