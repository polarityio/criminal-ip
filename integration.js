const async = require('async');
const request = require('request');
const _ = require('lodash');

let Logger;

function startup(logger) {
  Logger = logger;
}

function doLookup(entities, options, cb) {
  const lookupResults = [];
  async.each(
    entities,
    (entity, done) => {
      const requestOptions = {
        uri: 'https://api.criminalip.io/v1/ip/data',
        qs: {
          ip: entity.value,
          full: true
        },
        headers: {
          'x-api-key': options.apiKey
        },
        json: true
      };

      request(requestOptions, (err, response, body) => {
        if (err) {
          return done({
            detail: 'HTTP Error',
            err
          });
        }

        //Logger.trace({ body, status: response.statusCode }, 'Lookup response body');

        if (body.status === 200) {
          lookupResults.push({
            entity,
            data: {
              summary: getSummaryTags(body),
              details: {
                // Select data to send to template
                tags: body.tags,
                inboundScore: scoreToHumanReadable(body.score.inbound),
                outboundScore: scoreToHumanReadable(body.score.outbound),
                ip_category: getUniqueCategories(body),
                domain: body.domain,
                portSummary: createPortSummary(body)
              }
            }
          });
          done();
        } else {
          Logger.error(
            { status: body.status, body },
            'Unexpected HTTP Status Code Received'
          );
          done({
            detail: body.message
              ? body.message
              : `Unexpected HTTP Status Code Received: ${body.status}`,
            body
          });
        }
      });
    },
    (err) => {
      Logger.trace({ lookupResults }, 'Lookup Results');
      cb(err, lookupResults);
    }
  );
}

function getSummaryTags(body) {
  const tags = [];
  const inScore = scoreToHumanReadable(body.score.inbound);
  const outScore = scoreToHumanReadable(body.score.outbound);
  tags.push(`Inbound Score: ${inScore.percent}%`);
  tags.push(`Outbound Score: ${outScore.percent}%`);
  return tags;
}

/**
 * Criminal IP scores are an integer from 0 to 5
 *
 * 1: Safe
 * 2: Low
 * 3: Moderate
 * 4: Dangerous
 * 5: Critical
 *
 * We convert the numeric score a human readable score and a percent
 * @param score
 */
function scoreToHumanReadable(score) {
  const scoreToHuman = {
    0: 'Safe', // unsure if a 0 score is possible
    1: 'Safe',
    2: 'Low',
    3: 'Moderate',
    4: 'Dangerous',
    5: 'Critical'
  };

  return {
    score,
    display: scoreToHuman[score],
    percent: (score / 5) * 100
  };
}

/**
 * Return an array of unique open port numbers
 * @param body
 */
function createPortSummary(body){
  const uniquePorts = new Set();
  body.port.data.forEach(port => {
    uniquePorts.add(port.open_port_no);
  });
  return Array.from(uniquePorts);
}

function getUniqueCategories(body) {
  return _.get(body, 'ip_category.data', []).reduce((accum, item) => {
    if (item.detect_source.length > 0) {
      accum.push(item);
    }
    return accum;
  }, []);
}

module.exports = {
  startup,
  doLookup
};
