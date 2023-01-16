const _ = require('lodash');
const Bottleneck = require('bottleneck');
const cache = require('memory-cache');
const { setLogger } = require('./src/logger');
const { ApiRequestError, parseErrorToReadableJSON } = require('./src/errors');
const request = require('./src/polarity-request');

let Logger;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);
const MAX_DOMAINS = 250;
const MAX_LOOKUP_QUEUE_SIZE_PER_API_KEY = 15;
const bottlneckApiKeyCache = new cache.Cache();

function startup(logger) {
  Logger = logger;
  setLogger(Logger);
}

async function doLookup(entities, options, cb) {
  try {
    Logger.trace({ entities }, 'doLookup');
    const lookupResults = [];

    let limiter = bottlneckApiKeyCache.get(options.apiKey);

    if (!limiter) {
      limiter = new Bottleneck({
        id: options.apiKey,
        maxConcurrent: 1,
        highWater: MAX_LOOKUP_QUEUE_SIZE_PER_API_KEY,
        strategy: Bottleneck.strategy.OVERFLOW
      });
      bottlneckApiKeyCache.put(options.apiKey, limiter);
    }

    const tasks = entities.map(async (entity) => {
      try {
        return await limiter.schedule(() => lookupIp(entity, options));
      } catch (limiterError) {
        if (limiterError instanceof Bottleneck.BottleneckError) {
          return {
            entity,
            data: {
              summary: ['Search Limit Reached'],
              details: {
                apiLimitReached: true
              }
            }
          };
        } else {
          throw limiterError;
        }
      }
    });
    const results = await Promise.all(tasks);

    //Logger.info({ results }, 'lookup results');

    results.forEach((result) => {
      lookupResults.push(result);
    });

    cb(null, lookupResults);
  } catch (error) {
    const errorAsPojo = parseErrorToReadableJSON(error);
    Logger.error({ error: errorAsPojo }, 'Error in doLookup');
    return cb(errorAsPojo);
  }
}

async function lookupIp(entity, options) {
  if (!isValidIP(entity)) {
    return {
      entity,
      data: null
    };
  }

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

  const { body, statusCode } = await request.request(requestOptions);

  Logger.trace({ body, status: statusCode }, 'Lookup response body');

  // Note, the criminalIP API does not use the HTTP statusCode to signal errors.  The HTTP status code is
  // always 200 and then they set the "status" property on the returned payload (body), to the actual
  // status code.
  if (body.status === 200) {
    if (body.domain && Array.isArray(body.domain.data)) {
      body.domain.totalResults = body.domain.data.length;
      body.domain.data = body.domain.data.slice(0, MAX_DOMAINS);
      body.domain.isTruncated = true;
    }

    return {
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
    };
  } else {
    // Note, the criminalIP API does not use the HTTP statusCode to signal errors.  The HTTP status code is
    // always 200 and then they set the "status" property on the returned payload (body), to the actual
    // status code.
    Logger.error({ status: body.status, body }, 'Unexpected HTTP Status Code Received');
    throw new ApiRequestError(
      body.message
        ? body.message
        : `Unexpected status code ${body.status} received when making request to CriminalIP API`,
      {
        body,
        statusCode,
        requestOptions
      }
    );
  }
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
 * Ignore Private IPs, as well as IPs in the range 0.0.0.0/8 (CriminalIP will return a 400 error for these
 * as it does not consider them valid).
 * @param entity
 * @returns {boolean}
 */
function isValidIP(entity) {
  if (
    entity.isPrivateIP ||
    IGNORED_IPS.has(entity.value) ||
    entity.value.startsWith('0.')
  ) {
    return false;
  }
  return true;
}

/**
 * Return an array of unique open port numbers
 * @param body
 */
function createPortSummary(body) {
  const uniquePorts = new Set();
  body.port.data.forEach((port) => {
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

function retrySearch({ data: { entity } }, options, cb) {
  Logger.trace({ entity }, 'onMessage Entity');
  doLookup([entity], options, (err, lookupResults) => {
    if (err) return cb(err);
    Logger.trace({ lookupResults }, 'onMessage lookup results');
    const lookupResult = lookupResults[0];

    if (lookupResult && lookupResult.data && lookupResult.data === null) {
      cb(null, {
        summary: ['No Results Found'],
        details: {
          noResultsFound: true,
          isRetry: true
        }
      });
    } else {
      lookupResult.data.details.isRetry = true;
      cb(null, lookupResult.data);
    }
  });
}

module.exports = {
  startup,
  doLookup,
  onMessage: retrySearch
};
