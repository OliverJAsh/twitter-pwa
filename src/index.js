import { Server, createServer } from 'http';
import { getLatestPublication } from '../src/publication';
import express from 'express';
import Validation from 'data.validation';
import fetch from 'node-fetch';
import querystring from 'querystring';
import { randomBytes as randomBytesCb } from 'crypto';
import denodeify from 'denodeify';
import { max, toPairs, sortBy, flatten } from 'lodash';
import { createHmac } from 'crypto';
import session from 'express-session';

const randomBytes = denodeify(randomBytesCb);

const app = express();

app.use(session({ secret: 'keyboard cat' }));

const twitterConsumerKey = process.env.TWITTER_CONSUMER_KEY;
const twitterConsumerSecret = process.env.TWITTER_CONSUMER_SECRET;
const twitterCallbackURL = 'http://127.0.0.1:8080/auth/callback';
const twitterApiURL = 'https://api.twitter.com';

// https://dev.twitter.com/oauth/overview/creating-signatures
const createOauthSignature = ({ method, baseUrl, parameters, oauthTokenSecret }) => {
    const parametersString = sortBy(
        toPairs(parameters)
            .map(([ key, value ]) => [ encodeURIComponent(key), encodeURIComponent(value) ]),
        ([ key, value ]) => key
    )
        .map(pair => pair.join('='))
        .join('&');

    const signatureBaseString = `${method}&${encodeURIComponent(baseUrl)}&${encodeURIComponent(parametersString)}`;
    const signingKey = `${encodeURIComponent(twitterConsumerSecret)}&${encodeURIComponent(oauthTokenSecret)}`
    const signature = createHmac('sha1', signingKey).update(signatureBaseString).digest('base64')

    return signature;
};

const createNonce = () => randomBytes(32).then(buffer => (
    buffer.toString('base64').replace(/[^\w]/g, '')
));

const stringifyQueryParamsObj = (oauthParams) => (
    toPairs(oauthParams)
        .map(([ key, value ]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join('&')
);

const oauthHeaderFromObj = (oauthParams) => (
    toPairs(oauthParams)
        .map(([ key, value ]) => `${encodeURIComponent(key)}="${encodeURIComponent(value)}"`)
        .join(', ')
);

// https://dev.twitter.com/oauth/overview/authorizing-requests#collecting-parameters
const getOauthParams = (maybeOAuthRequestOrAccessToken) => (
    createNonce().then(nonce => (
        Object.assign({}, {
            oauth_callback: twitterCallbackURL,
            oauth_consumer_key: twitterConsumerKey,
            oauth_nonce: nonce,
            oauth_signature_method: 'HMAC-SHA1',
            oauth_timestamp: parseInt((Date.now() / 1000).toFixed(0)),
            oauth_version: '1.0',
        }, (
            maybeOAuthRequestOrAccessToken !== undefined
                ? { oauth_token: maybeOAuthRequestOrAccessToken, }
                : {}
        ))
    ))
);

const fetchFromTwitter = ({
    maybeOAuthRequestOrAccessToken,
    oauthAccessTokenSecret,
    baseUrlPath,
    method,
    otherParams,
}) => {
    return getOauthParams(maybeOAuthRequestOrAccessToken).then(oauthParams => {
        const baseUrl = `${twitterApiURL}${baseUrlPath}`;
        const parameters = Object.assign({}, oauthParams, otherParams);
        const oauthSignature = createOauthSignature({
            method,
            baseUrl,
            parameters,
            oauthTokenSecret: oauthAccessTokenSecret
        });
        const oauthHeader = oauthHeaderFromObj(
            Object.assign({}, oauthParams, { oauth_signature: oauthSignature })
        );

        const paramsStr = Object.keys(otherParams).length > 0
            ? `?${stringifyQueryParamsObj(otherParams)}`
            : '';
        const url = `${baseUrl}${paramsStr}`;
        return fetch(url, {
            method,
            headers: { 'Authorization': `OAuth ${oauthHeader}` }
        })
    });
}

const getRequestToken = () => {
    return fetchFromTwitter({
        oauthAccessTokenSecret: '',
        baseUrlPath: `/oauth/request_token`,
        method: 'POST',
        otherParams: {},
    })
        .then(response => (
            response.text().then(text => {
                if (response.ok) {
                    const parsed = querystring.parse(text)
                    return {
                        oauthToken: parsed.oauth_token,
                        oauthTokenSecret: parsed.oauth_token_secret,
                        oauthCallbackConfirmed: parsed.oauth_callback_confirmed,
                    }
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${text}`)
                }
            })
        ))
}

const getAccessToken = ({ oauthRequestToken, oauthVerifier }) => {
    return fetchFromTwitter({
        maybeOAuthRequestOrAccessToken: oauthRequestToken,
        oauthAccessTokenSecret: '',
        baseUrlPath: `/oauth/access_token?oauth_verifier=${oauthVerifier}`,
        method: 'POST',
        otherParams: {},
    })
        .then(response => (
            response.text().then(text => {
                if (response.ok) {
                    const parsed = querystring.parse(text)
                    return {
                        oauthToken: parsed.oauth_token,
                        oauthTokenSecret: parsed.oauth_token_secret,
                        userId: parsed.user_id,
                        screenName: parsed.screen_name,
                        xAuthExpires: parsed.x_auth_expires,
                    }
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${text}`)
                }
            })
        ))
};

class ApiError {
    constructor(props) { // { statusCode: number, message: string }
        Object.assign(this, props)
    }
}

class ApiErrors {
    constructor(errors) { // Array<ApiError>
        this.statusCode = max(errors.map(error => error.statusCode))
        this.errors = errors;
    }
}

// type ApiResponse<T> = Validation<Array<ApiError>, T>

// TODO: Dedupe
const limit = 800;
// This is the max allowed
// TODO: Dedupe
const pageSize = 200;

// yields ApiResponse<Tweet[]>
// if last tweet, recurse
// if no last tweet, do nothing (e.g. empty timeline)
const pageThroughTwitterTimeline = async function* ({ oauthAccessToken, oauthAccessTokenSecret }) {
    const recurse = async function* (maybeMaxId = undefined) {
        const response = await fetchFromTwitter({
            maybeOAuthRequestOrAccessToken: oauthAccessToken,
            oauthAccessTokenSecret,
            baseUrlPath: '/1.1/statuses/home_timeline.json',
            method: 'GET',
            otherParams: Object.assign({},
                {
                    count: pageSize,
                },
                maybeMaxId !== undefined ? { max_id: maybeMaxId } : {}
            )
        })
        const result = await handleTwitterResponse(response)
        yield result;
        // Delegate to an empty iterable
        yield* result.fold(() => [], async function* (json) {
            const maybeLastTweet = json[json.length - 1];
            if (maybeLastTweet) {
                const lastTweet = maybeLastTweet;
                yield* recurse(lastTweet.id_str)
            }
        })
    }

    yield* recurse()
}

// when ok, should return json
// when not ok and status is 429, return error
// when not ok and status is not recognised, return error
const handleTwitterResponse = async response => {
    if (response.ok) {
        const json = await response.json();
        return Validation.Success(json);
    } else {
        if (response.status === 429) {
            return Validation.Failure([new ApiError({
                statusCode: 429,
                message: 'Twitter API rate limit exceeded'
            })])
        } else {
            return Validation.Failure([new ApiError({
                statusCode: 500,
                // TODO: Include actual "unknown" errors here
                message: 'Unknown error response from Twitter API'
            })])
        }
    }
}

// https://dev.twitter.com/web/sign-in/implementing
app.get('/auth', (req, res, next) => {
    getRequestToken()
        .then(requestTokenResponse => (
            res
                .status(302)
                .location(`${twitterApiURL}/oauth/authenticate?oauth_token=${requestTokenResponse.oauthToken}`)
                .end()
        ))
        .catch(next);
});
app.get('/auth/callback', (req, res, next) => {
    getAccessToken({ oauthRequestToken: req.query.oauth_token, oauthVerifier: req.query.oauth_verifier })
        .then(accessTokenResponse => {
            // TODO:
            req.session.oauthAccessToken = accessTokenResponse.oauthToken;
            req.session.oauthAccessTokenSecret = accessTokenResponse.oauthTokenSecret;
            res.redirect('/');
        })
        .catch(next);
});
app.get('/', (req, res, next) => {
    // TODO: If logged in helper
    if (req.session.oauthAccessToken) {
        const pages = pageThroughTwitterTimeline({
            oauthAccessToken: req.session.oauthAccessToken,
            oauthAccessTokenSecret: req.session.oauthAccessTokenSecret
        });
        getLatestPublication(pages)
            .then(apiResponse => {
                apiResponse.cata({
                    Failure: apiErrorsList => {
                        const apiErrors = new ApiErrors(apiErrorsList)
                        const messages = apiErrors.errors.map(error => error.message)
                        res
                            .status(apiErrors.statusCode)
                            .send(
                                `<p>Errors:</p><ul>${messages.map(message => (
                                    `<li>${message}</li>`
                                )).join(' ')}</ul>`
                            )
                    },
                    Success: tweets => res.send((
                        `<ol>${tweets.map((tweet) => (
                            `<li>${tweet.created_at} @${tweet.user.screen_name}: ${tweet.text}</li>`
                        )).join('')}</ul>`
                    ))
                })
            })
            .catch(next);
    } else {
        res.send('Not authenticated');
    }
})

const onListen = (server) => {
    const { port } = server.address();

    console.log(`Server running on port ${port}`);
};

const httpServer = createServer(app);
httpServer.listen(8080, () => onListen(httpServer));
