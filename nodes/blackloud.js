let _server_url = "https://api.blackloud.com";

module.exports = function(RED) {
    function DoBlkdLogin(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        node.username = config.username;
        node.password = config.password;

        this.on('input', function(msg) {
            // convert to upper case
            var digestRequest = require('request-digest')(node.username, node.password);
            digestRequest.request({
                host: _server_url,
                path: '/v1/user/login',
                method: 'GET',
                port: 443,
                json: true,
            }, function(error, response, body) {
                if (error) {
                    msg.payload = error;
                    node.send(msg);
                    return;
                }

                msg.payload = body;
                node.send(msg);
            });
        });
    }
    RED.nodes.registerType("blkd-login", DoBlkdLogin);
}