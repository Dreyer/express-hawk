"use strict";

var hawk = require('../');

function getCredentials(id) {
    return {
        id: '1',
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'sha256',
        user: 'steve'
    };
}

var ttlSec = 300; // 5 mins
var url = 'http://www.example.org/foobar';
var bewit = hawk.getToken(getCredentials(), url, ttlSec);

url += '?bewit=' + bewit;

console.log(url);