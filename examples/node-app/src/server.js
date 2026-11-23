// Synthetic demo server for the dep-radar example.
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const lodash = require('lodash');

const app = express();
app.use(bodyParser.json());

app.get('/health', (req, res) => {
  res.json({ ok: true, version: '2.4.0' });
});

app.get('/metrics', async (req, res) => {
  const upstream = await axios.get(process.env.METRICS_URL);
  res.json(lodash.pick(upstream.data, ['cpu', 'memory', 'requests']));
});

app.listen(process.env.PORT || 8080);
