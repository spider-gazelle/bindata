abstract class BinData
  # Base class for every error raised while (de)serializing. Carries the failing
  # type, field and field type when known, so they can be inspected by a `rescue`.
  class CustomException < Exception
    getter klass : String?
    getter field : String?
    getter field_type : String?

    def initialize(message, ex : Exception)
      super(message, ex)
    end

    def initialize(message)
      super(message)
    end
  end

  # Raised when a field's `verify:` callback returns false.
  class VerificationException < CustomException; end

  # Raised when a `verify:` callback fails while writing a field.
  class WritingVerificationException < VerificationException
    def initialize(@klass, @field, @field_type)
      super("Failed to verify writing #{field_type} at #{klass}.#{field}")
    end
  end

  # Raised when a `verify:` callback fails while reading a field.
  class ReadingVerificationException < VerificationException
    def initialize(@klass, @field, @field_type)
      super("Failed to verify reading #{field_type} at #{klass}.#{field}")
    end
  end

  # Wraps any error raised while reading a field, tagged with its location.
  class ParseError < CustomException
    def initialize(@klass, @field, ex : Exception)
      super("Failed to parse #{klass}.#{field}", ex)
    end
  end

  # Wraps any error raised while writing a field, tagged with its location.
  class WriteError < CustomException
    def initialize(@klass, @field, ex : Exception)
      super("Failed to write #{klass}.#{field}", ex)
    end
  end
end
