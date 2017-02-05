import { FunctifiedAsync } from './functify'
import { Server, createServer } from 'http';
import express from 'express';
import Validation from 'data.validation';
import fetch from 'node-fetch';
import querystring from 'querystring';
import { randomBytes as randomBytesCb } from 'crypto';
import denodeify from 'denodeify';
import { max, uniqBy, toPairs, sortBy, flatten } from 'lodash';
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

const limit = 800;
// This is the max allowed
const pageSize = 200;

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
        const json = await response.json();
        if (response.ok) {
            yield Validation.Success(json);
            const maybeLastTweet = json[json.length - 1];
            if (maybeLastTweet) {
                const lastTweet = maybeLastTweet;
                yield* recurse(lastTweet.id_str)
            } else {
                yield Validation.Failure([new ApiError({
                    statusCode: 500,
                    message: 'Expected tweet'
                })])
            }
        } else {
            if (response.status === 429) {
                yield Validation.Failure([new ApiError({
                    statusCode: 429,
                    message: 'Twitter API rate limit exceeded'
                })])
            } else {
                yield Validation.Failure([new ApiError({
                    statusCode: 500,
                    // TODO: Include actual "unknown" errors here
                    message: 'Unknown error response from Twitter API'
                })])
            }
        }
    }

    yield* recurse()
}

// Array<Validation<A, B>> => Validation<Array<A>, Array<B>>
// https://github.com/origamitower/folktale/issues/71
const sequenceValidations = validations => (
    validations
        .reduce((acc, validation) => (
            Validation.Success(a => b => a.concat(b)).ap(acc).ap(validation)
        ), Validation.of([]))
)

const getLatestPublication = async ({ oauthAccessToken, oauthAccessTokenSecret }) => {
    const nowDate = new Date()
    const publicationHour = 6
    const isTodaysDueForPublication = nowDate.getHours() >= publicationHour
    // If the time is the past publication hour, the publication date is
    // today else it is yesterday.
    const publicationDate = new Date(
        nowDate.getFullYear(),
        nowDate.getMonth(),
        nowDate.getDate() - (isTodaysDueForPublication ? 0 : 1),
        publicationHour
    )
    // Publication date - 1 day
    const previousPublicationDate = new Date(
        publicationDate.getFullYear(),
        publicationDate.getMonth(),
        publicationDate.getDate() - 1,
        publicationDate.getHours()
    )

    // Lazily page through tweets in the timeline to find the publication
    // range.
    // Array<ApiResponse<Tweet>>
    const tweetApiResponses = await new FunctifiedAsync(pageThroughTwitterTimeline({ oauthAccessToken, oauthAccessTokenSecret }))
        // We request by max ID, and since the response is inclusive of the max
        // ID tweet, the paging could continue infinitely. This prevents that.
        // We're not forcing x requests, this is a limit applied lazily.
        .take(Math.ceil(limit / pageSize))
        // Move the array to the outside, so we can flatten the inner iterable
        // AsyncIterable<Validation<Left, Array<Right>>> => AsyncIterable<Array<Validation<Left, Right>>>
        // AsyncIterable<ApiResponse<Array<Tweet>>> => AsyncIterable<Array<ApiResponse<Tweet>>>
        .map(apiResponse => (
            apiResponse.fold(
                apiErrorsList => [Validation.Failure(apiErrorsList)],
                tweets => tweets.map(tweet => Validation.Success(tweet))
            )
        ))
        .flatten() // AsyncIterable<Array<ApiResponse<Tweet>>> => AsyncIterable<ApiResponse<Tweet>>
        .dropWhile(apiResponse => (
            apiResponse
                .map(tweet => new Date(tweet.created_at) >= publicationDate)
                .getOrElse(false)
        ))
        // TODO: Rename to takeWhile
        .takeUntil(apiResponse => (
            apiResponse
                .map(tweet => new Date(tweet.created_at) < previousPublicationDate)
                .getOrElse(false)
        ))
        .toArray();
    const tweetsApiResponse = sequenceValidations(tweetApiResponses)
        // Since the max ID parameter is inclusive, there will be duplicates where
        // the pages interleave. This removes them.
        .map(tweets => uniqBy(tweets, tweet => tweet.id_str))

    return tweetsApiResponse;
};

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
        getLatestPublication({
            oauthAccessToken: req.session.oauthAccessToken,
            oauthAccessTokenSecret: req.session.oauthAccessTokenSecret
        })
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
