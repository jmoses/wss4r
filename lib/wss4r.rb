require "time"
require "base64"
require "rexml/document"

require "soap/rpc/driver"


# Monkey Patch for integration between soap4r and actionwebservice
module SOAP
  SOAPNamespaceTag = 'env'
  XSDNamespaceTag  = 'xsd'
  XSINamespaceTag  = 'xsi'
end
