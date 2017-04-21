/*
	-- TLV command format ( 3-Level TLV ) --
	HEADER LENGTH1 0xff 0xff LENGTH2 TYPE_A LENGTH_A VALUE_A TYPE_B LENGTH_B VALUE_B ...
*/
exports.generateTLVcmd = function(ca_type, ca_class, cmd, val) {

    if (typeof(val) === 'object')
        val = JSON.stringify(val);

    // TLV cmd header : 2-bytes for Type(0x00, 0x01), 2-bytes for Reserverd(0x00, 0x00)
    var TLV_HEADER = [0x00, 0x01, 0x00, 0x00];

    // fixed 2-bytes (0xff, 0xff) after TLV head
    var FIXED_SECTION = [0xff, 0xff];

    // TLV cmd header definition
    // maintains Type Length Value of every header items
    // if there's no value and length, then it's useless item here.
    var CA_TITLE = {
        CA_PREFIX: 0xffff,
        CA_CMD_TYPE: { type: 0x0000, value: ca_type, length: 6 + 2 },
        CA_CLASS: { type: 0x0001, value: ca_class, length: 6 + 2 },
        CA_CMD: { type: 0x0002, value: cmd, length: 6 + cmd.length },
        CA_VAL: { type: 0x0003, value: val, length: 6 + val.length },
        CA_PID: 0x0004,
        CA_TIME: 0x0005,
        CA_USER: 0x0006,
        CA_NONCE: 0x0007,
        CA_SERIAL: 0x0008,
        CA_CODE: 0x0009
    };

    // total length of the CA_TITLE
    var CA_TITLE_LENGTH = CA_TITLE.CA_CMD_TYPE.length +
        CA_TITLE.CA_CLASS.length +
        CA_TITLE.CA_CMD.length +
        CA_TITLE.CA_VAL.length;

    // put in length and make it a 4-bytes array
    function lengthToBytes(len) {
        var bytes = new Uint8Array(4);
        bytes[0] = len >> 24;
        bytes[1] = len >> 16;
        bytes[2] = len >> 8;
        bytes[3] = len;
        return bytes;
    }

    // convert the TYPE_A LENGTH_A VALUE_A section to a byte array
    function getPartialTLV(type, value, len) {
        var length = 2 + 4 + len; // type(2-bytes) + length(2-bytes) + value.length
        var bytes = new Uint8Array(length);
        var lenBytes = lengthToBytes(len);

        // type : always 2-bytes long
        bytes[0] = type >> 8;
        bytes[1] = type;

        // length : always 4-bytes long
        bytes[2] = lenBytes[0];
        bytes[3] = lenBytes[1];
        bytes[4] = lenBytes[2];
        bytes[5] = lenBytes[3];

        // value :  
        switch (typeof(value)) {
            case 'number':
                for (var i = 6, j = len - 1; i < length; i++, j--)
                    bytes[i] = value >> j * 8;
                break;
            case 'string':
                for (var i = 6, j = 0; i < length; i++, j++)
                    bytes[i] = value.charCodeAt(j);
                break;
            default:
                logger.log('debug', 'unknown value type ... stop!');
        }
        return bytes;
    }

    // merge all byte arrays as one
    function mergeTLV(ary) {
        // counts the whole byte length
        var length = 0;
        ary.forEach(function(item) {
            length += item.byteLength;
        });

        // and declare a new byte array to put them in
        var cmd = new Uint8Array(length);
        var offset = 0;
        ary.forEach(function(item, idx) {
            offset += ((idx == 0) ? 0 : ary[idx - 1].byteLength);
            cmd.set(item, offset);
        });
        return cmd;
    }

    // collects all byte arrays and merge it as one later
    var tlvByteArray = [
        new Uint8Array(TLV_HEADER),
        lengthToBytes(CA_TITLE_LENGTH + 4 + 2),
        new Uint8Array(FIXED_SECTION),
        lengthToBytes(CA_TITLE_LENGTH),
        getPartialTLV(CA_TITLE.CA_CMD_TYPE.type, CA_TITLE.CA_CMD_TYPE.value, 2),
        getPartialTLV(CA_TITLE.CA_CLASS.type, CA_TITLE.CA_CLASS.value, 2),
        getPartialTLV(CA_TITLE.CA_CMD.type, CA_TITLE.CA_CMD.value, CA_TITLE.CA_CMD.value.length),
        getPartialTLV(CA_TITLE.CA_VAL.type, CA_TITLE.CA_VAL.value, CA_TITLE.CA_VAL.value.length)
    ];

    var tlvcmd = mergeTLV(tlvByteArray);
    var buffer = require('buffer').Buffer; // do base64 encoding on bytecode
    var base64cmd = new buffer(tlvcmd).toString('base64');
    return base64cmd;
}