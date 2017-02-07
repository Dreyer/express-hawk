"use strict";

var hawk = require('hawk');

var TOKEN_KEY = 'bewit';

/**
 * Hawk Middleware
 *
 * Returns a function that could be used as a middleware, to check an hawk
 * session exists and is valid.
 *
 * The middleware checks that the request is authenticated with hawk, and sign
 * the response.
 */
function getMiddleware(config) {
    var options = config.options || {};
    var getSession = config.getSession;
    var setSession = config.setSession;
    var sendError = config.sendError;

    if (typeof sendError === 'undefined') {
        sendError = function (res, statusCode, reasonPhrase, payload) {
            res.status(statusCode).json(payload);
        };
    }

    // Encode payload as unicode string.
    function toUnicode(body) {
        return body.replace(/[\u007f-\uffff]/g, function (c) {
            return '\\u'+('0000'+c.charCodeAt(0).toString(16)).slice(-4);
        });
    }

    // Authentication guard to parse request.
    function guard(req, res, next) {
        // Check if a bewit is present in the query string.
        var isBewit = (typeof req.query[TOKEN_KEY] !== 'undefined');
        var authenticate = isBewit ? hawk.uri.authenticate
                                   : hawk.server.authenticate;

        if (typeof req.headers['x-forwarded-port'] !== 'undefined') {
            options.port = req.headers['x-forwarded-port'];
        }

        if (typeof req.headers['x-forwarded-host'] !== 'undefined') {
            options.host = req.headers['x-forwarded-host'];
        }

        // Express sub-apps will have a different mountpath than '/' and
        // applications using routers under a set path will alter the
        // req.url therefore we need to use of req.originalUrl.

        // Convert Express request object to Hawk compatible request object.
        var request = {
            method: req.method,
            url: req.originalUrl,
            headers: req.headers,
            port: req.port,
            host: req.hostname
        };

        var lookup = function (id, cb) {
            getSession(id, function (err, credentials) {
                if (err) {
                    sendError(res, 403, 'Forbidden');
                    return;
                }

                cb(err, credentials);
            });
        };

        var callback = function (err, credentials, artifacts) {
            var payload = null;
            var statusCode = 401;
            var reasonPhrase = 'Unauthorized';

            if (err) {
                if (err.isBoom === true) {
                    if (err.output.payload) {
                        payload = err.output.payload;
                        statusCode = payload.statusCode;
                        reasonPhrase = payload.error;
                    }

                    if (err.isMissing) {
                        // In case no supported authentication was specified
                        // (and we don't need to create the session),  challenge
                        // the client.
                        res.set('WWW-Authenticate',
                            err.output.headers['WWW-Authenticate']);
                        sendError(res, statusCode, reasonPhrase, payload);
                        return;
                    }

                    if (err.output.headers) {
                        for (var name in err.output.headers) {
                            res.set(name, err.output.headers[name]);
                        }
                    }

                    sendError(res, statusCode, reasonPhrase, payload);
                    return;
                }
            }

            // There are no credentials, tell the client we need Hawk.
            if (credentials === null) {
                res.set('WWW-Authenticate', 'Hawk');
                sendError(res, statusCode, reasonPhrase);
                return;
            }

            setSession(req, res, credentials, function () {
                // Only do this once.
                if (res._hawkEnabled) {
                    next();
                    return;
                }

                // Keep a copy of the original send function.
                var send = res.send;
                res._hawkEnabled = true;

                // Rewrite the res.send function to sign all responses
                // with a Server-Authorization header from Hawk.
                res.send = function hawkSend(body) {
                    /*
                    if (typeof artifacts.host === 'undefined') {
                        console.log('Artifacts missing host:', artifacts);
                        console.log('statusCode: ', res.statusCode);
                        console.log('isBewit: ', isBewit);
                        console.log(request);
                    }
                    */

                    payload = toUnicode(body);

                    // A bewit provides short-term access to a protected
                    // resource to a third party without access to the
                    // credentials, therefore they will not be able to verify
                    // the a signed header anyway.
                    if ( ! isBewit) {
                        var header = hawk.server.header(credentials,
                            artifacts, {
                            payload: payload,
                            contentType: res.get('Content-Type')
                        });

                        res.set('Server-Authorization', header);
                    }

                    send.call(res, payload);
                };

                next();
            });
        };

        authenticate(request, lookup, options, callback);
    }

    return guard;
}

function getToken(credentials, uri, ttlSec, ext) {
    return hawk.uri.getBewit(uri, {
        credentials: credentials,
        ttlSec: ttlSec,
        ext: ext
    });
}

module.exports = {
    getMiddleware: getMiddleware,
    getToken: getToken,
    TOKEN_KEY: TOKEN_KEY
};