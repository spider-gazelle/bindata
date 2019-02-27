class BinData; end

require "./bindata/bitfield"

class BinData
  macro inherited
    PARTS = [] of Nil
    INDEX = [-1]
    BIT_PARTS = [] of Nil

    macro finished
      __build_methods__
    end
  end

  @@bit_fields = [] of BitField

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

        {% elsif part[0] == "bitfield" %}
          %bitfield = @@bit_fields[{{part[1]}}]
          %bitfield.read(io, __format__)

          # Apply the values (with their correct type)
          {% for name, value in BIT_PARTS[part[1]] %}
            %value = %bitfield[{{name.id.stringify}}]
            @{{name}} = %value.as({{value[0]}})
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

        {% elsif part[0] == "bitfield" %}
          # Apply any values
          {% for name, value in BIT_PARTS[part[1]] %}
            {% if value[1] %}
              %value = ({{value[1]}}).call
              @{{name}} = %value || @{{name}}
            {% end %}

            @@bit_fields[{{part[1]}}][{{name.id.stringify}}] = @{{name}}.not_nil!
          {% end %}

          @@bit_fields[{{part[1]}}].write(io, __format__)
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
  {% for vartype in ["UInt8", "Int8", "UInt16", "Int16", "UInt32", "Int32", "UInt64", "Int64", "UInt128", "Int128"] %}
    {% name = vartype.downcase.id %}

    macro {{name}}(name, onlyif = nil, value = nil)
      \{% PARTS << {"basic", name.id, {{vartype.id}}, onlyif, nil, value} %}
      property \{{name.id}} : {{vartype.id}}?
    end
  {% end %}

  macro string(name, onlyif = nil, length = nil, value = nil, encoding = nil)
    {% PARTS << {"string", name.id, "String".id, onlyif, length, value, encoding} %}
    property {{name.id}} : String?
	end

  macro bits(size, name, value = nil)
    %field = @@bit_fields[{{INDEX[0]}}]
    %field.bits({{size}}, {{name.id.stringify}})

    {% if size <= 8 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt8".id, value} %}
      property {{name.id}} : UInt8?
    {% elsif size <= 16 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt16".id, value} %}
      property {{name.id}} : UInt16?
    {% elsif size <= 32 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt32".id, value} %}
      property {{name.id}} : UInt32?
    {% elsif size <= 64 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt64".id, value} %}
      property {{name.id}} : UInt64?
    {% elsif size <= 128 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt128".id, value} %}
      property {{name.id}} : UInt128?
    {% else %}
      {{ "bits greater than 128 are not supported".id }}
    {% end %}
  end

  macro bit_field(onlyif = nil, &block)
    @@bit_fields << BitField.new
    {% INDEX[0] = INDEX[0] + 1 %}
    {% BIT_PARTS << {} of Nil => Nil %}

    {{block.body}}

    @@bit_fields[{{INDEX[0]}}].apply
    {% PARTS << {"bitfield", INDEX[0], nil, onlyif, nil, nil} %}
  end
end
