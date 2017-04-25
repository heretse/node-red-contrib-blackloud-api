let TlvCommand = require('../lib/tlv-command');

console.log(
    TlvCommand.generateTLVcmd(0x0001, 0x0001, "event_notify", '{"event_type": "0", "firstDay": 0, "rainPredicts": [0, 0, 1, 1, 0, 1, 0]}')
);