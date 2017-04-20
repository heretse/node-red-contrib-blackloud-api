let _server_url = "https://api.blackloud.com";

module.exports = function(RED) {
    function DoBlkdLogin(config) {
        RED.nodes.createNode(this, config);
        var node = this;
        node.username = config.username;
        node.password = config.password;

        // Access the node's context object
        var context = node.context();

        this.on('input', function(msg) {
            var _userInfo = context.get('userInfo');
            var _globalSession = context.get('globalSession');
            if (_globalSession && (new Date(_globalSession.expiration)).getTime() > (new Date()).getTime()) {
                msg.payload = { info: _userInfo, global_session: _globalSession };
                node.send(msg);
                return;
            }

            context.set('userInfo', null);
            context.set('globalSession', null);

            // call login api
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
                    this.status({ fill: "red", shape: "ring", text: "login failed" });
                    node.send(msg);
                    return;
                }

                msg.payload = { info: body.info, global_session: body.global_session };
                context.set('userInfo', body.info);
                context.set('globalSession', body.global_session);

                node.status({ fill: "green", shape: "dot", text: "login success" });
                node.send(msg);
            });
        });
    }
    RED.nodes.registerType("blkd-login", DoBlkdLogin);

    function SendTlvCommand(config) {
        this.on('input', function(msg) {
            RED.nodes.createNode(this, config);
            var node = this;

        });
    }

    RED.nodes.registerType("blkd-send-tlv-command", SendTlvCommand);
}