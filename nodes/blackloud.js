module.exports = function(RED) {
    let _server_url = "https://api.blackloud.com";
    let TlvCommand = require('../lib/tlv-command');
    var https = require("follow-redirects").https;
    var urllib = require("url");

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

    function GenerateTlvCommand(config) {
        RED.nodes.createNode(this, config);
        var node = this;

        node.cmdType = config.cmdType;
        node.cmdClass = config.cmdClass;
        node.cmdName = config.cmdName;
        node.cmdValue = config.cmdValue;

        this.on('input', function(msg) {
            msg.payload = TlvCommand.generateTLVcmd(parseInt(node.cmdType, 16), parseInt(node.cmdClass, 16), node.cmdName, node.cmdValue);
            node.send(msg);
        });
    }

    RED.nodes.registerType("blkd-generate-tlv-command", GenerateTlvCommand);

    function SendMessage(config) {
        RED.nodes.createNode(this, config);
        var node = this;

        if (RED.settings.httpRequestTimeout) {
            this.reqTimeout = parseInt(RED.settings.httpRequestTimeout) || 120000;
        } else {
            this.reqTimeout = 120000;
        }

        this.on('input', function(msg) {
            var url = _server_url + "/mec_msg/v1/send";

            var opts = urllib.parse(url);
            opts.method = "POST";
            opts.headers = { "content-type": "application/json" };

            var payload = JSON.stringify(msg.payload);

            if (opts.headers['content-length'] == null) {
                if (Buffer.isBuffer(payload)) {
                    opts.headers['content-length'] = payload.length;
                } else {
                    opts.headers['content-length'] = Buffer.byteLength(payload);
                }
            }

            var req = https.request(opts, function(res) {
                res.setEncoding('utf8');
                msg.statusCode = res.statusCode;
                msg.headers = res.headers;
                msg.payload = "";

                res.on('data', function(chunk) {
                    msg.payload += chunk;
                });

                res.on('end', function() {
                    if (node.metric()) {
                        // Calculate request time
                        var diff = process.hrtime(preRequestTimestamp);
                        var ms = diff[0] * 1e3 + diff[1] * 1e-6;
                        var metricRequestDurationMillis = ms.toFixed(3);
                        node.metric("duration.millis", msg, metricRequestDurationMillis);
                        if (res.client && res.client.bytesRead) {
                            node.metric("size.bytes", msg, res.client.bytesRead);
                        }
                    }

                    try {
                        msg.payload = JSON.parse(msg.payload);
                    } catch (e) {
                        node.warn(RED._("httpin.errors.json-error"));
                    }

                    node.send(msg);
                    node.status({});
                });
            });

            req.setTimeout(node.reqTimeout, function() {
                node.error(RED._("common.notification.errors.no-response"), msg);
                setTimeout(function() {
                    node.status({ fill: "red", shape: "ring", text: "common.notification.errors.no-response" });
                }, 10);
                req.abort();
            });
            req.on('error', function(err) {
                node.error(err, msg);
                msg.payload = err.toString() + " : " + url;
                msg.statusCode = err.code;
                node.send(msg);
                node.status({ fill: "red", shape: "ring", text: err.code });
            });
            if (payload) {
                req.write(payload);
            }
            req.end();
        });
    }

    RED.nodes.registerType("blkd-send-message", SendMessage);
}