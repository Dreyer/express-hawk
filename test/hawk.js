/* jshint expr: true */
/* jshint maxlen: 200 */

"use strict";

var hawk = require('hawk');
var express = require('express');
var request = require('request');
var assert = require('chai').assert;

var middleware = require('../').getMiddleware;
var token = require('../').getToken;
var tokenKey = require('../').TOKEN_KEY;

var credentials = {
    id: '1',
    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    algorithm: 'sha256',
    user: 'mocha.js'
};

function getExistingSession(tokenId, cb) {
    cb(null, { key: credentials.key, algorithm: 'sha256' });
}

function getNonExistingSession(tokenId, cb) {
    cb(null, null);
}

function setSession(req, res, credentials, done) {
    done();
}

function replyOK(req, res) {
    res.status(200).json({ key: 'value' });
}

var app = express();
var sub = express();

sub.get('/require-session', middleware({
    getSession: getExistingSession,
    setSession: setSession }), replyOK);

app.use('/sub', sub); // mount the sub app

var router = express.Router();

router.get('/require-session', middleware({
    getSession: getExistingSession,
    setSession: setSession }), replyOK);

app.use('/router', router);

app.get('/require-session-bewit', middleware({
    getSession: getExistingSession,
    setSession: setSession }), replyOK);
app.post('/require-session', middleware({
    getSession: getExistingSession,
    setSession: setSession }), replyOK);
app.post('/require-invalid-session', middleware({
    getSession: getNonExistingSession,
    setSession: setSession }), replyOK);

app.get('/', function (req, res) {
    res.send('hello world');
});

var port = 8081;
var host = 'localhost';
var endpoint = 'http://' + host + ':' + port;

function getHawkOptions(url, method) {
    var header = hawk.client.header(url, method, {
        credentials: credentials,
        ext: 'mocha.js'
    });

    return {
        url: url,
        method: method,
        headers: {
            'Authorization': header.field
        }
    };
}

var server;

describe('middleware', function () {
    before(function (done) {
        server = app.listen(port, function () {
            done();
        });
    });

    after(function (done) {
        server.close(function () {
            done();
        });
    });

    it('should return hello world', function (done) {
        request.get(endpoint + '/', function (err, res, body) {
            if (err) done(err);
            assert.equal('200', res.statusCode);
            assert.equal('hello world', body);
            done();
        });
    });

    it('should challenge the client if no auth is provided', function (done) {
        request.post(endpoint + '/require-session', function (err, res, body) {
            if (err) done(err);
            assert.equal('401', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"statusCode":401,"error":"Unauthorized"}', body);
            done();
        });
    });

    it('should accept a valid hawk session', function (done) {
        request(getHawkOptions(endpoint + '/require-session', 'POST'), function (err, res, body) {
            if (err) done(err);
            assert.equal('200', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"key":"value"}', body);
            done();
        });
    });

    it('should accept a valid hawk session for sub-app', function (done) {
        request(getHawkOptions(endpoint + '/sub/require-session', 'GET'), function (err, res, body) {
            if (err) done(err);
            assert.equal('200', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"key":"value"}', body);
            done();
        });
    });

    it('should accept a valid hawk session behind a router', function (done) {
        request(getHawkOptions(endpoint + '/router/require-session', 'GET'), function (err, res, body) {
            if (err) done(err);
            assert.equal('200', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"key":"value"}', body);
            done();
        });
    });

    it('should reject an invalid hawk session', function (done) {
        request(getHawkOptions(endpoint + '/require-invalid-session', 'POST'), function (err, res, body) {
            if (err) done(err);
            assert.equal('401', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"statusCode":401,"error":"Unauthorized","message":"Unknown credentials","attributes":{"error":"Unknown credentials"}}', body);
            done();
        });
    });

    it('should reject with bad request on malformed headers', function (done) {
        var options = {
            url: endpoint + '/require-session',
            method: 'POST',
            headers: {
                'Authorization': 'Hawk MALFORMED'
            }
        };

        request(options, function (err, res, body) {
            if (err) done(err);
            assert.equal('400', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"statusCode":400,"error":"Bad Request","message":"Bad header format"}', body);
            done();
        });
    });

    it('should reject with unauthorized with no bewit', function (done) {
        request.get(endpoint + '/require-session-bewit?foo=bar', function (err, res, body) {
            if (err) done(err);
            assert.equal('401', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"statusCode":401,"error":"Unauthorized"}', body);
            done();
        });
    });

    it('should reject with bad request for invalid bewit', function (done) {
        request.get(endpoint + '/require-session-bewit?' + tokenKey + '=foobar', function (err, res, body) {
            if (err) done(err);
            assert.equal('400', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"statusCode":400,"error":"Bad Request","message":"Invalid bewit structure"}', body);
            done();
        });
    });

    it('should create url with bewit', function (done) {
        var ttlSec = 300; // 5 mins
        var url = endpoint + '/require-session-bewit';
        var bewit = token(credentials, url, ttlSec);

        url += '?' + tokenKey + '=' + bewit;

        request.get(url, function (err, res, body) {
            if (err) done(err);
            assert.equal('200', res.statusCode);
            assert.equal('application/json; charset=utf-8', res.headers['content-type']);
            assert.equal('{"key":"value"}', body);
            done();
        });
    });
});