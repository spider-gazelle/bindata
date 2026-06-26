module ASN1
  # Base class for every ASN.1 error, so callers can `rescue ASN1::Error` to catch
  # any ASN.1 decode/encode failure at once.
  class Error < Exception; end

  # Raised by a typed accessor when the element's tag class/number doesn't match
  # the type being requested.
  class InvalidTag < Error; end

  # Raised when an object identifier string or encoding is malformed.
  class InvalidObjectId < Error; end

  # Raised when a payload is too short / malformed for the requested type.
  class InvalidPayload < Error; end

  # Raised when a declared content length exceeds `ASN1::BER#max_content_length`.
  class ContentTooLarge < Error; end

  # Raised when a BER length is malformed or exceeds the representable range.
  class InvalidLength < Error; end
end
