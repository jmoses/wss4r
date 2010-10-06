module WSS4R
  module Security
    module Xml

      class Reference
	attr_reader :uri
	
	def initialize(element, ref_element = nil, prefix_list = nil)
      @ref_element = ref_element
      @transforms = Array.new()
      @prefix_list = prefix_list
      @uri = element.attribute("URI").to_s()[1..-1] #remove leading #

      elements = XPath.match(element, "Transforms/Transform")
      elements.each{|e|
        @transforms.push(e.attribute("Algorithm"))
      }
      elements = XPath.match(element, "DigestMethod")
      elements.each{|e|
        @digest_algorithm = e.attribute("Algorithm")
      }
      elements = XPath.match(element, "DigestValue")
      elements.each{|e|
        @digest_value = e.text().strip()
      }
      # @ref_element = XPath.first(element.document, "//*[@wsu:Id='"+@uri+"']")
	end	
	
	def verify()
          trans_element = nil
          @transforms.each{|transform_algorithm|
            transformer = TransformerFactory::get_instance(transform_algorithm)
            transformer.prefix_list=(@prefix_list)
            trans_element = transformer.canonicalize_element(@ref_element)
            @ref_element = transformer.preserve_element # canonicalize_element does NOT alter @ref_element - this means it will fail if there is more than one Transform
          }
          if (@transforms.size() == 0)
            transformer = TransformerFactory::get_instance("http://www.w3.org/2001/10/xml-exc-c14n#")
            transformer.prefix_list=(@prefix_list)
            trans_element = transformer.canonicalize_element(@ref_element)
          end
          # trans_element = @ref_element.to_s
          digester = DigestFactory::get_instance(@digest_algorithm.value())
          digest = digester.digest_b64(trans_element).strip()
          # p digest.strip() + " <-----  #{@digest_value}"
          return true if (digest == @digest_value)
          false
	end
      end

    end
  end
end