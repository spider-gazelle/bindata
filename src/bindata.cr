class BinData; end

require "./bindata/bitfield"

class BinData
  macro inherited
    PARTS = [] of Nil

    macro finished
      __build_methods__
    end
  end

  @@bit_fields = [] of BitField
  @@current_field : BitField? = nil

  def __format__ : IO::ByteFormat
    IO::ByteFormat::SystemEndian
  end

  macro endian(format)
    def __format__ : IO::ByteFormat
      {% format = format.id.stringify %}
      {% if format == "litte" %}
      	IO::ByteFormat::LittleEndian
      {% elsif format == "big" %}
				IO::ByteFormat::BigEndian
      {% elsif format == "network" %}
				IO::ByteFormat::NetworkEndian
      {% else %}
				IO::ByteFormat::SystemEndian
      {% end %}
  	end
  end

  def read(io : IO)
  end

	def write(io : IO)
  end

  macro __build_methods__
    def read(io : IO) : IO
      # Support inheritance
      super(io)

      {% for part in PARTS %}
        {% if part[3] %}
          %onlyif = ({{part[3]}}).call
          if %onlyif
        {% end %}

      	{% if part[0] == "basic" %}
        	@{{part[1]}} = io.read_bytes({{part[2]}}, __format__)

     		{% elsif part[0] == "string" %}
      		{% if part[4] %}
    				# There is a length calculation
    				%size = ({{part[4]}}).call.not_nil!
    				%buf = Bytes.new(%size)
          	io.read(%buf)
          	@{{part[1]}} = String.new(%buf)
  				{% else %}
    				# Assume the string is 0 terminated
    				@{{part[1]}} = io.gets('\0')
  				{% end %}
    		{% end %}

        {% if part[3] %}
          end
        {% end %}
      {% end %}

      io
    end

		def write(io : IO) : IO
      # Support inheritance
      super(io)

      {% for part in PARTS %}
        {% if part[3] %}
          %onlyif = ({{part[3]}}).call
          if %onlyif
        {% end %}

        {% if part[5] %}
          # check if we need to configure the value
          %value = ({{part[5]}}).call
					@{{part[1]}} = %value || @{{part[1]}}
        {% end %}

      	{% if part[0] == "basic" %}
        	io.write_bytes(@{{part[1]}}.not_nil!, __format__)

     		{% elsif part[0] == "string" %}
					io.write(@{{part[1]}}.not_nil!.to_slice)
      		{% if !part[4] %}
						io.write_byte('\0')
  				{% end %}
    		{% end %}

        {% if part[3] %}
          end
        {% end %}
      {% end %}

      io
    end
  end

	# PARTS:
  #	0: parse type
  # 1: var_name
  # 2: class
  # 3: if_proc
  # 4: length
  # 5: value
  # 6: encoding
  macro uint32(name, onlyif = nil, value = nil)
    {% PARTS << {"basic", name.id, "UInt32".id, onlyif, nil, value} %}
    property {{name.id}} : UInt32?
  end

	macro int32(name, onlyif = nil, value = nil)
    {% PARTS << {"basic", name.id, "Int32".id, onlyif, nil, value} %}
    property {{name.id}} : Int32?
  end

  macro string(name, onlyif = nil, length = nil, encoding = nil)
    {% PARTS << {"string", name.id, "String".id, onlyif, length, nil, encoding} %}
    property {{name.id}} : String?
	end

  macro bits(size, name)
    %field = @@current_field.not_nil!
    %field.bits(size, name)

    {% if size <= 8 %}

      {% if size <= 8 %}
      {% end %}
    {% end %}
  end

  macro bit_field(&block)
    @@current_field = BitField.new
    @@bit_fields << @@current_field

    {{block.body}}

    @@current_field = nil
  end
end
