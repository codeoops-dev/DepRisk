const { parse } = require('example-lib');
const other = require('other-lib');
const { Api } = require('@scope/client');

function load(text) {
  return parse(text);
}

load('x');
other.help();
const api = new Api();
api.receive();
