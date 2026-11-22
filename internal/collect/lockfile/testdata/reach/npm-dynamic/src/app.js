const express = require('express');
const plugins = ['./a', './b'].map((p) => require(p));
