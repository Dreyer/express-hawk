"use strict";

var express = require('express');
var hawk = require('../');

var app = express();

var port = 8081;
var host = 'localhost';

function getCredentials(id) {
    return {
        id: '1',
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256',
        user: 'steve'
    };
}

var authentication = hawk.getMiddleware({
    getSession: function (id, cb) {
        console.log('middleware.getSession: id=' + id);

        // A function which pass to the cb the key and algorithm for the
        // given token id. First argument of the callback is a potential
        // error.

        var credentials = getCredentials(id);

        cb(null, credentials);
    },
    setSession: function (req, res, credentials, cb) {
        console.log('middleware.setSession: credentials=', credentials);

        // A function which stores a session for the given id and key.
        // Argument returned is a potential error.
        req.credentials = credentials;

        cb(null);
    }
});

app.use(function (req, res, next) {
    console.log('app.use: ' + req.method + ' ' + req.url);
    next();
});

app.get('/', function (req, res) {
    res.send('Hello World');
});

app.get('/secured', authentication);

app.listen(port, function () {
    console.log('app.listen: http://' + host + ':' + port + "\n");
});

