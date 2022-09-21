abstract class BinData
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

  class VerificationException < CustomException; end

  class WritingVerificationException < VerificationException
    def initialize(@klass, @field, @field_type)
      super("Failed to verify writing #{field_type} at #{klass}.#{field}")
    end
  end

  class ReadingVerificationException < VerificationException
    def initialize(@klass, @field, @field_type)
      super("Failed to verify reading #{field_type} at #{klass}.#{field}")
    end
  end

  class ParseError < CustomException
    def initialize(@klass, @field, ex : Exception)
      super("Failed to parse #{klass}.#{field}", ex)
    end
  end

  class WriteError < CustomException
    def initialize(@klass, @field, ex : Exception)
      super("Failed to write #{klass}.#{field}", ex)
    end
  end
end
