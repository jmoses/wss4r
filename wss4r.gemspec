WSS4R_FILES = %w{
  wss4r.gemspec
  lib/wss4r/aws/utils.rb
  CHANGELOG
  README
  gpl
  rubys
  copying
  lib/wss4r/config/config.rb
  lib/wss4r/rpc/proxy.rb
  lib/wss4r/rpc/router.rb
  lib/wss4r/rpc/wssdriver.rb
  lib/wss4r/security/crypto/certificate.rb
  lib/wss4r/security/crypto/cipher.rb
  lib/wss4r/security/crypto/hash.rb
  lib/wss4r/security/exceptions/exceptions.rb
  lib/wss4r/security/resolver.rb
  lib/wss4r/security/security.rb 
  lib/wss4r/security/util/hash_util.rb
  lib/wss4r/security/util/names.rb
  lib/wss4r/security/util/namespaces.rb
  lib/wss4r/security/util/reference_elements.rb
  lib/wss4r/security/util/soap_parser.rb
  lib/wss4r/security/util/transformer_factory.rb
  lib/wss4r/security/util/types.rb
  lib/wss4r/security/util/xmlcanonicalizer.rb
  lib/wss4r/security/util/xmlutils.rb
  lib/wss4r/security/xml/encrypted_data.rb
  lib/wss4r/security/xml/encrypted_key.rb
  lib/wss4r/security/xml/key_info.rb
  lib/wss4r/security/xml/reference.rb
  lib/wss4r/security/xml/reference_list.rb
  lib/wss4r/security/xml/security.rb
  lib/wss4r/security/xml/signature.rb
  lib/wss4r/security/xml/signature_value.rb
  lib/wss4r/security/xml/signed_info.rb
  lib/wss4r/security/xml/timestamp.rb
  lib/wss4r/security/xml/tokentypes.rb
  lib/wss4r/server/wssstandaloneserver.rb
  lib/wss4r/soap/processor.rb
  lib/wss4r/tokenresolver/authenticateuserresolver.rb
  lib/wss4r/tokenresolver/certificateresolver.rb
  lib/wss4r/tokenresolver/databaseresolver.rb
  lib/wss4r/tokenresolver/resolver.rb
  util/create_x509cert.rb
  util/DumpPrivateKey.class
  util/encrypt_xml.rb
  util/hints.txt
  util/xmlsec-verify.bat
  xml/out.xml
  xml/wse-encrypted-signed.xml
  xml/wse-signed-encrypted.xml
  xml/wse-signed.xml
  xml/wse-usernametoken-sign.xml
  xml/wse-usernametoken.xml
  xml/wss4r-encrypted-signed.xml
  xml/wss4r-encrypted.xml
  xml/wss4r-plain.xml
  xml/wss4r-signed-encrypted.xml
  xml/wss4r-signed.xml
  xml/wss4r-usernametoken.xml
  xml/xws-encrypted-signed-client.xml
  xml/xws-encrypted.xml
  xml/xws-signed-encrypted-client.xml
  xml/xws-signed-encrypted-server.xml
  xml/xws-signed-encrypted-server20.xml
  xml/xws-signed.xml
  xml/xws-usernametoken.xml
}

Gem::Specification.new do |s|
  s.name = "wss4r"
  s.version = "0.5.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Roland Schmitt", "Herval Freire"]

  s.date = "2005-12-22"
  s.description = "Partial implementation of some of the WS-Security standards on top of SOAP4R."
  
  s.files = WSS4R_FILES
  
  s.has_rdoc = false
  s.homepage = "http://rubyforge.org/projects/wss4r/"
  s.require_paths = ["lib", "xml"]
  s.rubyforge_project = "wss4r"
  s.rubygems_version = "1.3.5"
  s.summary = "Partial implementation of some of the WS-Security standards on top of SOAP4R."

  s.add_dependency("rubigen", [">= 1.0.6"])
  s.add_dependency("log4r", [">= 1.0.5"])
end
